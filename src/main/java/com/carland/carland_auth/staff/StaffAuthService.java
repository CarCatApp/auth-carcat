package com.carland.carland_auth.staff;

import com.carland.carland_auth.dto.request.UserRequest;
import com.carland.carland_auth.dto.response.UserResponse;
import com.carland.carland_auth.entity.StaffAccount;
import com.carland.carland_auth.enums.EnumMessagesLangValues;
import com.carland.carland_auth.enums.UserRoles;
import com.carland.carland_auth.exceptions.AuthApiException;
import com.carland.carland_auth.exceptions.MissingFieldException;
import com.carland.carland_auth.exceptions.PinLockedException;
import com.carland.carland_auth.exceptions.UserNotFoundException;
import com.carland.carland_auth.exceptions.UsernameAlreadyExistException;
import com.carland.carland_auth.exceptions.WrongPasswordException;
import com.carland.carland_auth.feign.CarlandBookingFeign;
import com.carland.carland_auth.jwt.CarlandPrincipal;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.repository.StaffAccountRepository;
import com.carland.carland_auth.staff.dto.StaffAuditRequest;
import com.carland.carland_auth.staff.dto.StaffDisableRequest;
import com.carland.carland_auth.staff.dto.StaffPasswordChangeRequest;
import com.carland.carland_auth.staff.dto.StaffProvisionRequest;
import com.carland.carland_auth.staff.dto.StaffProvisionResponse;
import com.carland.carland_auth.util.PhoneNumbers;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
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

    private final StaffAccountRepository staffAccountRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final CarlandBookingFeign carlandBookingFeign;
    private final StaffLoginAttemptService staffLoginAttemptService;

    @Value("${staff.access-token-seconds:18000}")
    private Long staffAccessTokenSeconds;

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
        if (staffAccountRepository.existsByPhoneNumber(phone)) {
            throw new UsernameAlreadyExistException(
                    EnumMessagesLangValues.USERNAME_ALREADY_EXISTS.getMessageByLang(acceptLanguage));
        }
        String email = normalizeEmail(request.getEmail());
        if (email != null && staffAccountRepository.existsByEmailIgnoreCase(email)) {
            throw new UsernameAlreadyExistException(
                    EnumMessagesLangValues.EMAIL_ALREADY_EXISTS.getMessageByLang(acceptLanguage));
        }

        String oneTime = UUID.randomUUID().toString();
        StaffAccount account = StaffAccount.builder()
                .phoneNumber(phone)
                .email(email)
                .staffPassword(passwordEncoder.encode(oneTime))
                .name(blankToNull(request.getName()))
                .surname(blankToNull(request.getSurname()))
                .role(role)
                .status(StaffAccountStatus.INVITED.name())
                .failedAttempts(0)
                .createdAt(LocalDateTime.now())
                .build();
        StaffAccount saved = saveNew(account, acceptLanguage);
        if (saved.getId() == null || saved.getId() < StaffIds.MIN_ID) {
            if (saved.getId() != null) {
                staffAccountRepository.delete(saved);
            }
            log.error("STAFF_ID_BELOW_MIN id={}", saved.getId());
            throw new AuthApiException("STAFF_ID_RANGE",
                    "Staff id sequence is below 100000000", HttpStatus.SERVICE_UNAVAILABLE);
        }
        log.info("STAFF_PROVISION_OK staffId={} role={}", saved.getId(), role);
        return StaffProvisionResponse.builder()
                .userId(saved.getId())
                .phoneNumber(phone)
                .oneTimePassword(oneTime)
                .build();
    }

    @Transactional
    public void disable(StaffDisableRequest request) {
        if (request == null || request.getUserId() == null) {
            throw new AuthApiException("MISSING_FIELD", "userId is required", HttpStatus.BAD_REQUEST);
        }
        StaffAccount account = staffAccountRepository.findById(request.getUserId()).orElse(null);
        if (account == null) {
            return;
        }
        account.setStatus(StaffAccountStatus.DISABLED.name());
        staffAccountRepository.save(account);
        log.info("STAFF_DISABLE_OK staffId={}", account.getId());
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

        StaffAccount account = phone != null
                ? staffAccountRepository.findByPhoneNumber(phone)
                : staffAccountRepository.findByEmailIgnoreCase(email);
        if (account == null || !isOpen(account)) {
            auditLogin(null, phone != null ? phone : email, false, "FAIL");
            throw new UserNotFoundException(EnumMessagesLangValues.STAFF_USER_NOT_FOUND.getMessageByLang(acceptLanguage));
        }

        staffLoginAttemptService.clearExpiredLock(account.getId());
        account = staffAccountRepository.findById(account.getId()).orElseThrow();
        String auditId = account.getPhoneNumber();
        LocalDateTime now = LocalDateTime.now();
        if (account.getLockedUntil() != null && account.getLockedUntil().isAfter(now)) {
            long remaining = Math.max(1, java.time.Duration.between(now, account.getLockedUntil()).getSeconds());
            auditLogin(account, auditId, false, "LOCKED");
            throw new PinLockedException(
                    EnumMessagesLangValues.PIN_LOCKED.getMessageByLang(acceptLanguage),
                    account.getLockedUntil(),
                    remaining);
        }

        if (account.getStaffPassword() == null || account.getStaffPassword().isBlank()
                || !passwordEncoder.matches(password, account.getStaffPassword())) {
            StaffLoginAttemptService.Result result = staffLoginAttemptService.recordWrongPassword(account.getId());
            if (result.locked()) {
                auditLogin(account, auditId, false, "LOCKED");
                throw new PinLockedException(
                        EnumMessagesLangValues.PIN_LOCKED.getMessageByLang(acceptLanguage),
                        result.lockedUntil(),
                        result.remainingSeconds());
            }
            auditLogin(account, auditId, false, "FAIL");
            throw new WrongPasswordException(EnumMessagesLangValues.STAFF_WRONG_PASSWORD.getMessageByLang(acceptLanguage));
        }

        staffLoginAttemptService.clearFailureState(account.getId());
        boolean invited = StaffAccountStatus.INVITED.name().equalsIgnoreCase(account.getStatus());
        String accessToken = jwtService.generateStaffAccessToken(
                account.getId(), account.getPhoneNumber(), account.getRole(),
                account.getName(), account.getSurname(), staffAccessTokenSeconds, invited);
        auditLogin(account, auditId, true, "OK");

        return UserResponse.builder()
                .accessToken(accessToken)
                .role(account.getRole())
                .userId(account.getId())
                .name(account.getName())
                .surname(account.getSurname())
                .phoneNumber(account.getPhoneNumber())
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
        StaffAccount account = staffAccountRepository.findById(principal.getUserId()).orElseThrow(() ->
                new AuthApiException("INVALID_ROLE", "not a booking staff user", HttpStatus.FORBIDDEN));
        if (!isStaffRole(account.getRole()) || StaffAccountStatus.DISABLED.name().equalsIgnoreCase(account.getStatus())) {
            throw new AuthApiException("INVALID_ROLE", "not a booking staff user", HttpStatus.FORBIDDEN);
        }

        boolean invited = StaffAccountStatus.INVITED.name().equalsIgnoreCase(account.getStatus());
        if (!invited) {
            if (request.getCurrentPassword() == null || request.getCurrentPassword().isBlank()) {
                throw new MissingFieldException(
                        EnumMessagesLangValues.STAFF_CURRENT_PASSWORD_REQUIRED.getMessageByLang(acceptLanguage));
            }
            if (account.getStaffPassword() == null
                    || !passwordEncoder.matches(request.getCurrentPassword(), account.getStaffPassword())) {
                throw new WrongPasswordException(EnumMessagesLangValues.STAFF_WRONG_PASSWORD.getMessageByLang(acceptLanguage));
            }
        }

        account.setStaffPassword(passwordEncoder.encode(request.getNewPassword()));
        account.setStatus(StaffAccountStatus.ACTIVE.name());
        staffAccountRepository.save(account);
        notifyCarlandActivated(account.getId());

        String accessToken = jwtService.generateStaffAccessToken(
                account.getId(), account.getPhoneNumber(), account.getRole(),
                account.getName(), account.getSurname(), staffAccessTokenSeconds, false);
        return UserResponse.builder()
                .accessToken(accessToken)
                .role(account.getRole())
                .userId(account.getId())
                .name(account.getName())
                .surname(account.getSurname())
                .phoneNumber(account.getPhoneNumber())
                .mustChangePassword(false)
                .message(EnumMessagesLangValues.SUCCESS.getMessageByLang(acceptLanguage))
                .build();
    }

    private StaffAccount saveNew(StaffAccount account, String acceptLanguage) {
        try {
            return staffAccountRepository.save(account);
        } catch (DataIntegrityViolationException ex) {
            throw new UsernameAlreadyExistException(
                    EnumMessagesLangValues.USERNAME_ALREADY_EXISTS.getMessageByLang(acceptLanguage));
        }
    }

    private void notifyCarlandActivated(Long staffId) {
        if (!StringUtils.hasText(internalToken)) {
            log.warn("STAFF_ACTIVATE_SKIP staffId={} reason=no_internal_token", staffId);
            return;
        }
        try {
            carlandBookingFeign.activateStaff(internalToken, staffId);
        } catch (Exception ex) {
            log.warn("STAFF_ACTIVATE_FEIGN_FAIL staffId={}", staffId);
        }
    }

    private void auditLogin(StaffAccount account, String phone, boolean success, String detail) {
        if (!StringUtils.hasText(internalToken)) {
            return;
        }
        try {
            carlandBookingFeign.auditStaff(internalToken, StaffAuditRequest.builder()
                    .action("LOGIN")
                    .actor(phone)
                    .userId(account == null ? null : account.getId())
                    .phoneNumber(phone)
                    .role(account == null ? null : account.getRole())
                    .detail(detail)
                    .success(success)
                    .build());
        } catch (Exception ex) {
            log.warn("STAFF_AUDIT_LOGIN_FAIL staffId={}", account == null ? null : account.getId());
        }
    }

    private static boolean isOpen(StaffAccount account) {
        if (!isStaffRole(account.getRole())) {
            return false;
        }
        return StaffAccountStatus.INVITED.name().equalsIgnoreCase(account.getStatus())
                || StaffAccountStatus.ACTIVE.name().equalsIgnoreCase(account.getStatus());
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
