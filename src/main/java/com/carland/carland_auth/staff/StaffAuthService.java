package com.carland.carland_auth.staff;

import com.carland.carland_auth.dto.request.UserRequest;
import com.carland.carland_auth.dto.response.UserResponse;
import com.carland.carland_auth.entity.RefreshToken;
import com.carland.carland_auth.entity.User;
import com.carland.carland_auth.enums.EnumMessagesLangValues;
import com.carland.carland_auth.enums.UserRoles;
import com.carland.carland_auth.enums.UserStatus;
import com.carland.carland_auth.exceptions.AuthApiException;
import com.carland.carland_auth.exceptions.MissingFieldException;
import com.carland.carland_auth.exceptions.PinLockedException;
import com.carland.carland_auth.exceptions.UserNotFoundException;
import com.carland.carland_auth.exceptions.UsernameAlreadyExistException;
import com.carland.carland_auth.exceptions.WrongPasswordException;
import com.carland.carland_auth.feign.CarlandBookingFeign;
import com.carland.carland_auth.jwt.CarlandPrincipal;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.repository.UserRepository;
import com.carland.carland_auth.service.interfaces.RefreshTokenService;
import com.carland.carland_auth.staff.dto.StaffAuditRequest;
import com.carland.carland_auth.staff.dto.StaffDisableRequest;
import com.carland.carland_auth.staff.dto.StaffPasswordChangeRequest;
import com.carland.carland_auth.staff.dto.StaffProvisionRequest;
import com.carland.carland_auth.staff.dto.StaffProvisionResponse;
import com.carland.carland_auth.util.PhoneNumbers;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class StaffAuthService {

    private static final int MIN_PASSWORD_LENGTH = 8;

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final CarlandBookingFeign carlandBookingFeign;
    private final StaffLoginAttemptService staffLoginAttemptService;

    @Value("${access.token.expiration}")
    private Long accessTokenExpiration;

    @Value("${carland.internal-token:}")
    private String internalToken;

    @Transactional
    public StaffProvisionResponse provision(StaffProvisionRequest request, String acceptLanguage) {
        if (request == null) {
            throw new HttpMessageConversionException(EnumMessagesLangValues.MISSING_BODY.getMessageByLang(acceptLanguage));
        }
        String phone = PhoneNumbers.normalize(request.getPhoneNumber());
        if (phone == null) {
            throw new MissingFieldException(EnumMessagesLangValues.MISSING_PHONE_NUMBER.getMessageByLang(acceptLanguage));
        }
        StaffPhones.assertAllowedOperator(phone, acceptLanguage);
        String role = request.getRole() == null ? "" : request.getRole().trim().toUpperCase();
        if (!UserRoles.PARTNER_ADMIN.name().equals(role) && !UserRoles.BRANCH_ADMIN.name().equals(role)) {
            throw new AuthApiException("INVALID_ROLE", "role must be PARTNER_ADMIN or BRANCH_ADMIN", HttpStatus.BAD_REQUEST);
        }
        if (userRepository.findByPhoneNumber(phone) != null) {
            throw new UsernameAlreadyExistException(
                    EnumMessagesLangValues.USERNAME_ALREADY_EXISTS.getMessageByLang(acceptLanguage));
        }
        String email = normalizeEmail(request.getEmail());
        if (email != null && userRepository.findByEmailIgnoreCase(email) != null) {
            throw new UsernameAlreadyExistException(
                    EnumMessagesLangValues.EMAIL_ALREADY_EXISTS.getMessageByLang(acceptLanguage));
        }

        String oneTime = UUID.randomUUID().toString();
        User user = User.builder()
                .phoneNumber(phone)
                .email(email)
                .name(blankToNull(request.getName()))
                .surname(blankToNull(request.getSurname()))
                .pin(passwordEncoder.encode(oneTime))
                .pinHash(null)
                .role(role)
                .status(UserStatus.INVITED.name())
                .createdAt(LocalDateTime.now())
                .failedPinAttempts(0)
                .build();
        userRepository.save(user);
        log.info("STAFF_PROVISION_OK userId={} role={}", user.getId(), role);
        return StaffProvisionResponse.builder()
                .userId(user.getId())
                .phoneNumber(phone)
                .oneTimePassword(oneTime)
                .build();
    }

    @Transactional
    public void disable(StaffDisableRequest request) {
        if (request == null || request.getUserId() == null) {
            throw new AuthApiException("MISSING_FIELD", "userId is required", HttpStatus.BAD_REQUEST);
        }
        User user = userRepository.findById(request.getUserId()).orElse(null);
        if (user == null) {
            return;
        }
        if (!isStaffRole(user.getRole())) {
            throw new AuthApiException("INVALID_ROLE", "not a booking staff user", HttpStatus.BAD_REQUEST);
        }
        user.setStatus(UserStatus.BLOCKED.name());
        userRepository.save(user);
        log.info("STAFF_DISABLE_OK userId={}", user.getId());
    }

    @Transactional
    public UserResponse login(UserRequest request, String acceptLanguage) {
        if (request == null) {
            throw new HttpMessageConversionException(EnumMessagesLangValues.MISSING_BODY.getMessageByLang(acceptLanguage));
        }
        String phone = StaffPhones.requireLoginPhone(request.getPhoneNumber(), acceptLanguage);
        String email = normalizeEmail(request.getEmail());
        String password = request.resolveCredential();
        if (password != null && password.length() < MIN_PASSWORD_LENGTH) {
            throw new AuthApiException("WEAK_PASSWORD",
                    EnumMessagesLangValues.STAFF_PASSWORD_TOO_SHORT.getMessageByLang(acceptLanguage),
                    HttpStatus.BAD_REQUEST);
        }
        if ((phone == null && email == null) || password == null) {
            throw new MissingFieldException(EnumMessagesLangValues.STAFF_LOGIN_MISSING.getMessageByLang(acceptLanguage));
        }

        User user = phone != null
                ? userRepository.findByPhoneNumber(phone)
                : userRepository.findByEmailIgnoreCase(email);
        if (user == null || UserStatus.DELETED.name().equalsIgnoreCase(user.getStatus())
                || UserStatus.BLOCKED.name().equalsIgnoreCase(user.getStatus())
                || !isStaffRole(user.getRole())) {
            auditLogin(null, phone != null ? phone : email, false, "FAIL");
            throw new UserNotFoundException(EnumMessagesLangValues.STAFF_USER_NOT_FOUND.getMessageByLang(acceptLanguage));
        }
        boolean invited = UserStatus.INVITED.name().equalsIgnoreCase(user.getStatus());
        boolean active = UserStatus.ACTIVE.name().equalsIgnoreCase(user.getStatus());
        if (!invited && !active) {
            auditLogin(user, user.getPhoneNumber(), false, "FAIL");
            throw new UserNotFoundException(EnumMessagesLangValues.STAFF_USER_NOT_FOUND.getMessageByLang(acceptLanguage));
        }

        staffLoginAttemptService.clearExpiredLock(user.getId());
        user = userRepository.findById(user.getId()).orElseThrow();
        String auditId = user.getPhoneNumber();
        LocalDateTime now = LocalDateTime.now();
        if (user.getPinLockedUntil() != null && user.getPinLockedUntil().isAfter(now)) {
            long remaining = Math.max(1, java.time.Duration.between(now, user.getPinLockedUntil()).getSeconds());
            auditLogin(user, auditId, false, "LOCKED");
            throw new PinLockedException(
                    EnumMessagesLangValues.PIN_LOCKED.getMessageByLang(acceptLanguage),
                    user.getPinLockedUntil(),
                    remaining);
        }

        if (user.getPin() == null || user.getPin().isBlank() || !passwordEncoder.matches(password, user.getPin())) {
            StaffLoginAttemptService.Result result = staffLoginAttemptService.recordWrongPassword(user.getId());
            if (result.locked()) {
                auditLogin(user, auditId, false, "LOCKED");
                throw new PinLockedException(
                        EnumMessagesLangValues.PIN_LOCKED.getMessageByLang(acceptLanguage),
                        result.lockedUntil(),
                        result.remainingSeconds());
            }
            auditLogin(user, auditId, false, "FAIL");
            throw new WrongPasswordException(EnumMessagesLangValues.STAFF_WRONG_PASSWORD.getMessageByLang(acceptLanguage));
        }

        staffLoginAttemptService.clearFailureState(user.getId());

        String accessToken = jwtService.generateAccessToken(user, accessTokenExpiration, invited);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        refreshToken.setUser(user);
        user.getRefreshTokens().add(refreshToken);
        userRepository.save(user);
        auditLogin(user, auditId, true, "OK");

        return UserResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .role(user.getRole())
                .userId(user.getId())
                .name(user.getName())
                .surname(user.getSurname())
                .phoneNumber(user.getPhoneNumber())
                .mustChangePassword(invited)
                .message(EnumMessagesLangValues.LOGIN_SUCCESS.getMessageByLang(acceptLanguage))
                .build();
    }

    @Transactional
    public UserResponse changePassword(StaffPasswordChangeRequest request, String acceptLanguage) {
        if (request == null || request.getNewPassword() == null || request.getNewPassword().isBlank()) {
            throw new MissingFieldException(EnumMessagesLangValues.MISSING_FIELDS.getMessageByLang(acceptLanguage));
        }
        if (request.getNewPassword().length() < MIN_PASSWORD_LENGTH) {
            throw new AuthApiException("WEAK_PASSWORD",
                    EnumMessagesLangValues.STAFF_PASSWORD_TOO_SHORT.getMessageByLang(acceptLanguage),
                    HttpStatus.BAD_REQUEST);
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof CarlandPrincipal principal)) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }
        User user = userRepository.findById(principal.getUserId()).orElseThrow(() ->
                new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED));
        if (!isStaffRole(user.getRole())) {
            throw new AuthApiException("INVALID_ROLE", "not a booking staff user", HttpStatus.FORBIDDEN);
        }

        boolean invited = UserStatus.INVITED.name().equalsIgnoreCase(user.getStatus());
        if (!invited) {
            if (request.getCurrentPassword() == null || request.getCurrentPassword().isBlank()) {
                throw new MissingFieldException(
                        EnumMessagesLangValues.STAFF_CURRENT_PASSWORD_REQUIRED.getMessageByLang(acceptLanguage));
            }
            if (user.getPin() == null || !passwordEncoder.matches(request.getCurrentPassword(), user.getPin())) {
                throw new WrongPasswordException(EnumMessagesLangValues.STAFF_WRONG_PASSWORD.getMessageByLang(acceptLanguage));
            }
        }

        user.setPin(passwordEncoder.encode(request.getNewPassword()));
        user.setStatus(UserStatus.ACTIVE.name());
        userRepository.save(user);
        notifyCarlandActivated(user.getId());

        String accessToken = jwtService.generateAccessToken(user, accessTokenExpiration, false);
        return UserResponse.builder()
                .accessToken(accessToken)
                .role(user.getRole())
                .userId(user.getId())
                .name(user.getName())
                .surname(user.getSurname())
                .phoneNumber(user.getPhoneNumber())
                .mustChangePassword(false)
                .message(EnumMessagesLangValues.SUCCESS.getMessageByLang(acceptLanguage))
                .build();
    }

    private void notifyCarlandActivated(Long userId) {
        if (!StringUtils.hasText(internalToken)) {
            log.warn("STAFF_ACTIVATE_SKIP userId={} reason=no_internal_token", userId);
            return;
        }
        try {
            carlandBookingFeign.activateStaff(internalToken, userId);
        } catch (Exception ex) {
            log.warn("STAFF_ACTIVATE_FEIGN_FAIL userId={}", userId);
        }
    }

    private void auditLogin(User user, String phone, boolean success, String detail) {
        if (!StringUtils.hasText(internalToken)) {
            return;
        }
        try {
            carlandBookingFeign.auditStaff(internalToken, StaffAuditRequest.builder()
                    .action("LOGIN")
                    .actor(phone)
                    .userId(user == null ? null : user.getId())
                    .phoneNumber(phone)
                    .role(user == null ? null : user.getRole())
                    .detail(detail)
                    .success(success)
                    .build());
        } catch (Exception ex) {
            log.warn("STAFF_AUDIT_LOGIN_FAIL userId={}", user == null ? null : user.getId());
        }
    }

    private static boolean isStaffRole(String role) {
        return UserRoles.PARTNER_ADMIN.name().equalsIgnoreCase(role)
                || UserRoles.BRANCH_ADMIN.name().equalsIgnoreCase(role);
    }

    private static String blankToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    static String normalizeEmail(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return raw.trim().toLowerCase();
    }
}
