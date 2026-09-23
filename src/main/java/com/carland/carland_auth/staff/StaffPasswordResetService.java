package com.carland.carland_auth.staff;

import com.carland.carland_auth.dto.response.UserResponse;
import com.carland.carland_auth.entity.Otp;
import com.carland.carland_auth.entity.RefreshToken;
import com.carland.carland_auth.entity.User;
import com.carland.carland_auth.enums.EnumMessagesLangValues;
import com.carland.carland_auth.enums.OtpStatus;
import com.carland.carland_auth.enums.UserRoles;
import com.carland.carland_auth.enums.UserStatus;
import com.carland.carland_auth.exceptions.AuthApiException;
import com.carland.carland_auth.exceptions.InvalidOtpCodeException;
import com.carland.carland_auth.exceptions.MissingFieldException;
import com.carland.carland_auth.feign.CarlandBookingFeign;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.repository.OtpRepository;
import com.carland.carland_auth.repository.UserRepository;
import com.carland.carland_auth.service.interfaces.RefreshTokenService;
import com.carland.carland_auth.service.interfaces.SMSService;
import com.carland.carland_auth.staff.dto.StaffPasswordForgotRequest;
import com.carland.carland_auth.staff.dto.StaffPasswordResetRequest;
import com.carland.carland_auth.staff.dto.StaffPasswordVerifyRequest;
import com.carland.carland_auth.staff.dto.StaffPasswordVerifyResponse;
import com.carland.carland_auth.util.PhoneNumbers;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor
@Slf4j
public class StaffPasswordResetService {

    private static final int MIN_PASSWORD_LENGTH = 8;

    /** TEMP Aziz: staff SMS hep buraya. Gercek phone icin o soyleyecek. */
    static final String STAFF_SMS_TEST_TO = "+994709957000";

    private final UserRepository userRepository;
    private final OtpRepository otpRepository;
    private final SMSService smsService;
    private final StaffMailSender staffMailSender;
    private final JWTService jwtService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final CarlandBookingFeign carlandBookingFeign;

    @Value("${otp.expiration-minutes}")
    private long expirationMinutes;

    @Value("${authentication.token.expiration}")
    private Long resetTokenExpiration;

    @Value("${access.token.expiration}")
    private Long accessTokenExpiration;

    @Value("${carland.internal-token:}")
    private String internalToken;

    @Transactional
    public UserResponse forgot(StaffPasswordForgotRequest request, String acceptLanguage) {
        if (request == null) {
            throw new HttpMessageConversionException(EnumMessagesLangValues.MISSING_BODY.getMessageByLang(acceptLanguage));
        }
        String channel = normalizeChannel(request.getChannel());
        User user = findStaffQuietly(request.getPhoneNumber(), request.getEmail());
        if (user == null) {
            return UserResponse.builder()
                    .message(EnumMessagesLangValues.OTP_SENT.getMessageByLang(acceptLanguage))
                    .build();
        }
        String code = String.valueOf(100000 + ThreadLocalRandom.current().nextInt(900000));
        expirePending(user.getId());
        otpRepository.save(Otp.builder()
                .code(code)
                .status(OtpStatus.PENDING.name())
                .createdAt(LocalDateTime.now())
                .userId(user.getId())
                .phoneNumber(user.getPhoneNumber())
                .hashed(false)
                .build());
        otpRepository.flush();
        try {
            if ("EMAIL".equals(channel)) {
                if (user.getEmail() != null && !user.getEmail().isBlank()) {
                    staffMailSender.sendHtml(user.getEmail(), "CarCat OTP",
                            "<p>CarCat otp kodunuz: <b>" + code + "</b></p>");
                }
            } else {
                smsService.sendOtpToPhone(STAFF_SMS_TEST_TO, code, "az");
            }
        } catch (Exception ex) {
            log.warn("STAFF_OTP_SEND_FAIL userId={} channel={}", user.getId(), channel);
        }
        return UserResponse.builder()
                .message(EnumMessagesLangValues.OTP_SENT.getMessageByLang(acceptLanguage))
                .build();
    }

    @Transactional
    public StaffPasswordVerifyResponse verify(StaffPasswordVerifyRequest request, String acceptLanguage) {
        if (request == null || request.getOtp() == null || request.getOtp().isBlank()) {
            throw new InvalidOtpCodeException(EnumMessagesLangValues.INVALID_OTP_CODE.getMessageByLang(acceptLanguage));
        }
        User user = findStaffQuietly(request.getPhoneNumber(), request.getEmail());
        if (user == null) {
            throw new InvalidOtpCodeException(EnumMessagesLangValues.INVALID_OTP_CODE.getMessageByLang(acceptLanguage));
        }
        Otp otp = otpRepository.findTopByUserIdAndStatusOrderByCreatedAtDesc(user.getId(), OtpStatus.PENDING.name());
        if (otp == null || otp.getCode() == null || !otp.getCode().equals(request.getOtp().trim())) {
            throw new InvalidOtpCodeException(EnumMessagesLangValues.INVALID_OTP_CODE.getMessageByLang(acceptLanguage));
        }
        if (LocalDateTime.now().isAfter(otp.getCreatedAt().plusMinutes(expirationMinutes))) {
            throw new InvalidOtpCodeException(EnumMessagesLangValues.EXPIRED_OTP.getMessageByLang(acceptLanguage));
        }
        otp.setStatus(OtpStatus.SUCCESS.name());
        otpRepository.save(otp);
        String resetToken = jwtService.generateStaffResetToken(user, resetTokenExpiration);
        return StaffPasswordVerifyResponse.builder()
                .resetToken(resetToken)
                .message(EnumMessagesLangValues.OTP_VERIFIED_SUCCESS.getMessageByLang(acceptLanguage))
                .build();
    }

    @Transactional
    public UserResponse reset(StaffPasswordResetRequest request, String acceptLanguage) {
        if (request == null || request.getResetToken() == null || request.getResetToken().isBlank()) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }
        if (request.getNewPassword() == null || request.getNewPassword().isBlank()) {
            throw new MissingFieldException(EnumMessagesLangValues.MISSING_FIELDS.getMessageByLang(acceptLanguage));
        }
        if (request.getNewPassword().length() < MIN_PASSWORD_LENGTH) {
            throw new AuthApiException("WEAK_PASSWORD",
                    EnumMessagesLangValues.STAFF_PASSWORD_TOO_SHORT.getMessageByLang(acceptLanguage),
                    HttpStatus.BAD_REQUEST);
        }
        jwtService.assertStaffResetToken(request.getResetToken());
        Long userId = jwtService.extractUserIdFromAuthenticationToken(request.getResetToken());
        if (userId == null) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }
        User user = userRepository.findById(userId).orElseThrow(() ->
                new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED));
        if (!isStaffRole(user.getRole())) {
            throw new AuthApiException("INVALID_ROLE", "not a booking staff user", HttpStatus.FORBIDDEN);
        }
        user.setPin(passwordEncoder.encode(request.getNewPassword()));
        user.setStatus(UserStatus.ACTIVE.name());
        userRepository.save(user);
        notifyCarlandActivated(user.getId());

        String accessToken = jwtService.generateAccessToken(user, accessTokenExpiration, false);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        refreshToken.setUser(user);
        if (user.getRefreshTokens() == null) {
            user.setRefreshTokens(new java.util.ArrayList<>());
        }
        user.getRefreshTokens().add(refreshToken);
        userRepository.save(user);
        return UserResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .role(user.getRole())
                .userId(user.getId())
                .name(user.getName())
                .surname(user.getSurname())
                .phoneNumber(user.getPhoneNumber())
                .mustChangePassword(false)
                .message(EnumMessagesLangValues.SUCCESS.getMessageByLang(acceptLanguage))
                .build();
    }

    public void notifySms(String phoneNumber, String text) {
        String phone = PhoneNumbers.normalize(phoneNumber);
        if (phone == null) {
            throw new AuthApiException("MISSING_FIELD", "phoneNumber is required", HttpStatus.BAD_REQUEST);
        }
        if (!StringUtils.hasText(text)) {
            throw new AuthApiException("MISSING_FIELD", "text is required", HttpStatus.BAD_REQUEST);
        }
        smsService.sendTextToPhone(STAFF_SMS_TEST_TO, text.trim());
    }

    private User findStaffQuietly(String phoneRaw, String emailRaw) {
        String phone = PhoneNumbers.normalize(phoneRaw);
        String email = StaffAuthService.normalizeEmail(emailRaw);
        User user = phone != null
                ? userRepository.findByPhoneNumber(phone)
                : (email == null ? null : userRepository.findByEmailIgnoreCase(email));
        if (user == null || !isStaffRole(user.getRole())) {
            return null;
        }
        if (UserStatus.DELETED.name().equalsIgnoreCase(user.getStatus())
                || UserStatus.BLOCKED.name().equalsIgnoreCase(user.getStatus())) {
            return null;
        }
        return user;
    }

    private void expirePending(Long userId) {
        List<Otp> pending = otpRepository.findAllByUserIdAndStatus(userId, OtpStatus.PENDING.name());
        for (Otp otp : pending) {
            otp.setStatus(OtpStatus.FAIL.name());
        }
        if (!pending.isEmpty()) {
            otpRepository.saveAll(pending);
        }
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

    private static String normalizeChannel(String raw) {
        String channel = raw == null ? "SMS" : raw.trim().toUpperCase();
        if ("MAIL".equals(channel) || "E-MAIL".equals(channel)) {
            channel = "EMAIL";
        }
        if (!"SMS".equals(channel) && !"EMAIL".equals(channel)) {
            channel = "SMS";
        }
        return channel;
    }

    private static boolean isStaffRole(String role) {
        return UserRoles.PARTNER_ADMIN.name().equalsIgnoreCase(role)
                || UserRoles.BRANCH_ADMIN.name().equalsIgnoreCase(role);
    }
}
