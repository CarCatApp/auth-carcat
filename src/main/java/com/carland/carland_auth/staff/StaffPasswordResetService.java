package com.carland.carland_auth.staff;

import com.carland.carland_auth.dto.response.UserResponse;
import com.carland.carland_auth.entity.StaffAccount;
import com.carland.carland_auth.entity.StaffOtp;
import com.carland.carland_auth.enums.EnumMessagesLangValues;
import com.carland.carland_auth.enums.OtpStatus;
import com.carland.carland_auth.enums.UserRoles;
import com.carland.carland_auth.exceptions.AuthApiException;
import com.carland.carland_auth.exceptions.InvalidOtpCodeException;
import com.carland.carland_auth.exceptions.MissingFieldException;
import com.carland.carland_auth.feign.CarlandBookingFeign;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.repository.StaffAccountRepository;
import com.carland.carland_auth.repository.StaffOtpRepository;
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

    private final StaffAccountRepository staffAccountRepository;
    private final StaffOtpRepository staffOtpRepository;
    private final StaffOtpHasher staffOtpHasher;
    private final SMSService smsService;
    private final StaffMailSender staffMailSender;
    private final JWTService jwtService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final CarlandBookingFeign carlandBookingFeign;
    private final StaffWorkplaceService staffWorkplaceService;

    @Value("${otp.expiration-minutes}")
    private long expirationMinutes;

    @Value("${authentication.token.expiration}")
    private Long resetTokenExpiration;

    @Value("${staff.access-token-seconds:18000}")
    private Long staffAccessTokenSeconds;

    @Value("${staff.otp.max-verify-attempts:3}")
    private int maxVerifyAttempts;

    @Value("${carland.internal-token:}")
    private String internalToken;

    @Transactional
    public UserResponse forgot(StaffPasswordForgotRequest request, String acceptLanguage) {
        if (request == null) {
            throw new HttpMessageConversionException(EnumMessagesLangValues.MISSING_BODY.getMessageByLang(acceptLanguage));
        }
        String channel = normalizeChannel(request.getChannel());
        StaffAccount account = findStaffQuietly(request.getPhoneNumber(), request.getEmail(), acceptLanguage);
        if (account == null) {
            return UserResponse.builder()
                    .message(EnumMessagesLangValues.OTP_SENT.getMessageByLang(acceptLanguage))
                    .build();
        }
        String code = String.valueOf(100000 + ThreadLocalRandom.current().nextInt(900000));
        expirePending(account.getId());
        staffOtpRepository.save(StaffOtp.builder()
                .staffAccountId(account.getId())
                .codeHash(staffOtpHasher.hash(code))
                .status(OtpStatus.PENDING.name())
                .verifyFailCount(0)
                .createdAt(LocalDateTime.now())
                .build());
        staffOtpRepository.flush();
        try {
            if ("EMAIL".equals(channel)) {
                if (account.getEmail() != null && !account.getEmail().isBlank()) {
                    staffMailSender.sendHtml(account.getEmail(), "CarCat OTP",
                            "<p>CarCat otp kodunuz: <b>" + code + "</b></p>");
                }
            } else {
                smsService.sendOtpToPhone(account.getPhoneNumber(), code, acceptLanguage);
            }
        } catch (Exception ex) {
            log.warn("STAFF_OTP_SEND_FAIL staffId={} channel={}", account.getId(), channel);
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
        StaffAccount account = findStaffQuietly(request.getPhoneNumber(), request.getEmail(), acceptLanguage);
        if (account == null) {
            throw new InvalidOtpCodeException(EnumMessagesLangValues.INVALID_OTP_CODE.getMessageByLang(acceptLanguage));
        }
        StaffOtp otp = staffOtpRepository.findTopByStaffAccountIdAndStatusOrderByCreatedAtDesc(
                account.getId(), OtpStatus.PENDING.name());
        if (otp == null || otp.getCodeHash() == null) {
            throw new InvalidOtpCodeException(EnumMessagesLangValues.INVALID_OTP_CODE.getMessageByLang(acceptLanguage));
        }
        if (LocalDateTime.now().isAfter(otp.getCreatedAt().plusMinutes(expirationMinutes))) {
            otp.setStatus(OtpStatus.FAIL.name());
            staffOtpRepository.save(otp);
            throw new InvalidOtpCodeException(EnumMessagesLangValues.EXPIRED_OTP.getMessageByLang(acceptLanguage));
        }
        if (!staffOtpHasher.matches(request.getOtp().trim(), otp.getCodeHash())) {
            int fails = otp.getVerifyFailCount() == null ? 0 : otp.getVerifyFailCount();
            fails = fails + 1;
            otp.setVerifyFailCount(fails);
            if (fails >= maxVerifyAttempts) {
                otp.setStatus(OtpStatus.FAIL.name());
            }
            staffOtpRepository.save(otp);
            throw new InvalidOtpCodeException(EnumMessagesLangValues.INVALID_OTP_CODE.getMessageByLang(acceptLanguage));
        }
        otp.setStatus(OtpStatus.SUCCESS.name());
        staffOtpRepository.save(otp);
        String resetToken = jwtService.generateStaffResetToken(
                account.getId(), account.getPhoneNumber(), resetTokenExpiration);
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
        Long staffId = jwtService.extractUserIdFromAuthenticationToken(request.getResetToken());
        if (staffId == null || staffId < StaffIds.MIN_ID) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }
        StaffAccount account = staffAccountRepository.findById(staffId).orElseThrow(() ->
                new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED));
        if (!isStaffRole(account.getRole())
                || StaffAccountStatus.DISABLED.name().equalsIgnoreCase(account.getStatus())) {
            throw new AuthApiException("INVALID_ROLE", "not a booking staff user", HttpStatus.FORBIDDEN);
        }
        staffWorkplaceService.assertOpen(account, acceptLanguage);
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

    public void notifySms(String phoneNumber, String text) {
        String phone = PhoneNumbers.normalize(phoneNumber);
        if (phone == null) {
            throw new AuthApiException("MISSING_FIELD", "phoneNumber is required", HttpStatus.BAD_REQUEST);
        }
        if (!StringUtils.hasText(text)) {
            throw new AuthApiException("MISSING_FIELD", "text is required", HttpStatus.BAD_REQUEST);
        }
        smsService.sendTextToPhone(phone, text.trim());
    }

    private StaffAccount findStaffQuietly(String phoneRaw, String emailRaw, String lang) {
        String phone = StaffPhones.requireLoginPhone(phoneRaw, lang);
        String email = StaffAuthService.normalizeEmail(emailRaw);
        StaffAccount account = phone != null
                ? staffAccountRepository.findByPhoneNumber(phone)
                : (email == null ? null : staffAccountRepository.findByEmailIgnoreCase(email));
        if (account == null || !isStaffRole(account.getRole())) {
            return null;
        }
        if (StaffAccountStatus.DISABLED.name().equalsIgnoreCase(account.getStatus())) {
            return null;
        }
        return account;
    }

    private void expirePending(Long staffId) {
        List<StaffOtp> pending = staffOtpRepository.findAllByStaffAccountIdAndStatus(staffId, OtpStatus.PENDING.name());
        for (StaffOtp otp : pending) {
            otp.setStatus(OtpStatus.FAIL.name());
        }
        if (!pending.isEmpty()) {
            staffOtpRepository.saveAll(pending);
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
