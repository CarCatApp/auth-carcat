package com.carland.carland_auth.new_users_version.service;

import com.carland.carland_auth.dto.request.UserRequest;
import com.carland.carland_auth.dto.response.UserResponse;
import com.carland.carland_auth.entity.*;
import com.carland.carland_auth.enums.EnumMessagesLangValues;
import com.carland.carland_auth.enums.OtpStatus;
import com.carland.carland_auth.enums.UserRoles;
import com.carland.carland_auth.enums.UserStatus;
import com.carland.carland_auth.exceptions.AuthApiException;
import com.carland.carland_auth.exceptions.PinLockedException;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.messaging.CustomerEnsurePublisher;
import com.carland.carland_auth.new_users_version.dto.AuthFlowResponse;
import com.carland.carland_auth.new_users_version.dto.NewOtpRequest;
import com.carland.carland_auth.new_users_version.dto.PinSetResponse;
import com.carland.carland_auth.repository.*;
import com.carland.carland_auth.service.AuthEndpointRateLimiter;
import com.carland.carland_auth.service.AuthFlowLogService;
import com.carland.carland_auth.service.OtpSendLockService;
import com.carland.carland_auth.service.OtpVerifyAttemptService;
import com.carland.carland_auth.service.PinAttemptService;
import com.carland.carland_auth.service.interfaces.RefreshTokenService;
import com.carland.carland_auth.service.interfaces.SMSService;
import com.carland.carland_auth.util.AfterCommit;
import com.carland.carland_auth.util.HashUtil;
import com.carland.carland_auth.util.PinValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;

@Service
@RequiredArgsConstructor
@Slf4j
public class NewUsersService {

    public static final String NEXT_SEND_OTP = "SEND_OTP";
    public static final String NEXT_PIN_CHECK = "PIN_CHECK";
    public static final String NEXT_SET_PIN = "SET_PIN";
    public static final String NEXT_VERIFY_OTP = "VERIFY_OTP";
    public static final String PURPOSE_REGISTER = "REGISTER";
    public static final String PURPOSE_RESET = "RESET";
    public static final String STAGE_SET_PIN = "SET_PIN";

    @Value("${authentication.token.expiration}")
    private Long authTokenExpiration;

    @Value("${access.token.expiration}")
    private Long accessTokenExpiration;

    @Value("${otp.expiration-minutes:3}")
    private long otpExpirationMinutes;

    @Value("${otp.new.resend-cooldown-seconds:30}")
    private long resendCooldownSeconds;

    @Value("${otp.new.max-sends-per-window:3}")
    private int maxSendsPerWindow;

    @Value("${otp.new.send-window-minutes:15}")
    private int sendWindowMinutes;

    @Value("${otp.new.phone-lock-minutes:5}")
    private int phoneLockMinutes;

    @Value("${otp.new.ip-lock-hours:24}")
    private int ipLockHours;

    private final UserRepository userRepository;
    private final JWTService jwtService;
    private final OtpRepository otpRepository;
    private final OtpRateLimitRepository otpRateLimitRepository;
    private final IpOtpRateLimitRepository ipOtpRateLimitRepository;
    private final ConsumedAuthTokenRepository consumedAuthTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenService refreshTokenService;
    private final SMSService smsService;
    private final Argon2PasswordEncoder argon2PasswordEncoder;
    private final PinAttemptService pinAttemptService;
    private final OtpVerifyAttemptService otpVerifyAttemptService;
    private final OtpSendLockService otpSendLockService;
    private final AuthEndpointRateLimiter authEndpointRateLimiter;
    private final CustomerEnsurePublisher customerEnsurePublisher;
    private final AuthFlowLogService authFlowLogService;

    @Transactional
    public AuthFlowResponse auth(UserRequest request, HttpServletRequest httpRequest, String acceptLanguage) {
        if (request == null) {
            throw new HttpMessageConversionException(EnumMessagesLangValues.MISSING_BODY.getMessageByLang(acceptLanguage));
        }
        String phone = normalizePhone(request.getPhoneNumber());
        if (phone == null) {
            throw new AuthApiException("INVALID_PHONE", "Invalid phone number.", HttpStatus.BAD_REQUEST);
        }

        authEndpointRateLimiter.check(phone, resolveClientIp(httpRequest));

        String requestedPurpose = request.getPurpose() == null ? null : request.getPurpose().trim().toUpperCase();
        User user = userRepository.findByPhoneNumber(phone);
        boolean hasPin = user != null && user.getPinHash() != null && !user.getPinHash().isBlank();
        boolean deleted = user != null && UserStatus.DELETED.name().equalsIgnoreCase(user.getStatus());
        boolean active = user != null && UserStatus.ACTIVE.name().equalsIgnoreCase(user.getStatus());
        // PIN_CHECK only for ACTIVE + pin_hash. OTP_VERIFIED / restart → SEND_OTP.
        boolean pinCheckEligible = hasPin && active && !deleted;

        // RESET with usable PIN → OTP reset path (next unchanged)
        if (PURPOSE_RESET.equals(requestedPurpose) && pinCheckEligible) {
            syncUserStatusForNext(user, phone, NEXT_SEND_OTP);
            String token = jwtService.generatePhoneAuthToken(phone, PURPOSE_RESET, authTokenExpiration);
            authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "AUTH_DECISION",
                    user.getId(), phone, null, PURPOSE_RESET, 200, null, null,
                    "next=" + NEXT_SEND_OTP + " pinCheckEligible=true requestedPurpose=RESET status=" + user.getStatus());
            return AuthFlowResponse.builder()
                    .authToken(token)
                    .next(NEXT_SEND_OTP)
                    .purpose(PURPOSE_RESET)
                    .message(EnumMessagesLangValues.OTP_SENT.getMessageByLang(acceptLanguage))
                    .build();
        }

        if (pinCheckEligible) {
            // ACTIVE + PIN — leave status ACTIVE; next unchanged
            String token = jwtService.generatePhoneAuthToken(phone, PURPOSE_REGISTER, authTokenExpiration);
            authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "AUTH_DECISION",
                    user.getId(), phone, null, PURPOSE_REGISTER, 200, null, null,
                    "next=" + NEXT_PIN_CHECK + " pinCheckEligible=true hasPin=true status=" + user.getStatus());
            return AuthFlowResponse.builder()
                    .authToken(token)
                    .next(NEXT_PIN_CHECK)
                    .purpose(PURPOSE_REGISTER)
                    .message(EnumMessagesLangValues.LOGIN_SUCCESS.getMessageByLang(acceptLanguage))
                    .build();
        }

        // SEND_OTP path: create user if missing; status → OTP_PENDING (incl. DELETED / restart)
        String priorStatus = user == null ? "null" : user.getStatus();
        syncUserStatusForNext(user, phone, NEXT_SEND_OTP);
        String token = jwtService.generatePhoneAuthToken(phone, PURPOSE_REGISTER, authTokenExpiration);
        User afterSync = userRepository.findByPhoneNumber(phone);
        authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "AUTH_DECISION",
                afterSync == null ? null : afterSync.getId(), phone, null, PURPOSE_REGISTER, 200, null, null,
                "next=" + NEXT_SEND_OTP + " pinCheckEligible=false hasPin=" + hasPin
                        + " active=" + active + " deleted=" + deleted
                        + " statusBefore=" + priorStatus
                        + " statusAfter=" + (afterSync == null ? "null" : afterSync.getStatus()));
        return AuthFlowResponse.builder()
                .authToken(token)
                .next(NEXT_SEND_OTP)
                .purpose(PURPOSE_REGISTER)
                .message(EnumMessagesLangValues.REGISTER_SUCCESS.getMessageByLang(acceptLanguage))
                .build();
    }

    /**
     * Align users.status with the step {@code next} forces — does not change API next/response contract.
     * Legacy-compatible ladder: OTP_PENDING → OTP_VERIFIED → ACTIVE (no CREATED in enum).
     */
    private void syncUserStatusForNext(User user, String phone, String next) {
        if (NEXT_PIN_CHECK.equals(next)) {
            return;
        }
        if (NEXT_SEND_OTP.equals(next)) {
            if (user == null) {
                userRepository.save(User.builder()
                        .phoneNumber(phone)
                        .createdAt(LocalDateTime.now())
                        .role(UserRoles.USER.name())
                        .status(UserStatus.OTP_PENDING.name())
                        .build());
                return;
            }
            // Re-onboard after DELETE: drop old PIN so REGISTER setPin is first-PIN, not "hadPin" gray zone.
            if (UserStatus.DELETED.name().equalsIgnoreCase(user.getStatus())) {
                user.setPinHash(null);
                user.setPin(null);
            }
            user.setStatus(UserStatus.OTP_PENDING.name());
            userRepository.save(user);
        }
    }

    /**
     * Hard rail: ACTIVE + PIN users must use PIN login or purpose=RESET (forgot PIN).
     * REGISTER OTP/setPin for them was accepted before and caused mass session revoke / logout.
     */
    private void assertRegisterPathAllowedForUser(User user, String purpose, String phone, String step,
                                                  String acceptLanguage) {
        if (!PURPOSE_REGISTER.equals(purpose)) {
            return;
        }
        if (user == null) {
            return;
        }
        boolean active = UserStatus.ACTIVE.name().equalsIgnoreCase(user.getStatus());
        boolean hasPin = user.getPinHash() != null && !user.getPinHash().isBlank();
        if (!(active && hasPin)) {
            return;
        }
        authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "PATH_REJECTED",
                user.getId(), phone, null, purpose, 409, "PIN_LOGIN_REQUIRED",
                "ACTIVE user with PIN cannot use REGISTER OTP/setPin",
                "step=" + step + " use PIN login or /auth purpose=RESET");
        throw new AuthApiException(
                "PIN_LOGIN_REQUIRED",
                EnumMessagesLangValues.PIN_LOGIN_REQUIRED.getMessageByLang(acceptLanguage),
                HttpStatus.CONFLICT);
    }

    @Transactional
    public AuthFlowResponse createAndSend(NewOtpRequest request, HttpServletRequest httpRequest, String acceptLanguage) {
        String authToken = requireAuthToken(request);
        assertNotConsumed(authToken);
        jwtService.assertPhoneAuthToken(authToken);

        String phone = jwtService.extractPhoneFromAuthToken(authToken);
        String purposeRaw = jwtService.extractAndLogPurposeFromAuthToken(authToken);
        String purpose = stripStage(purposeRaw);
        String ip = resolveClientIp(httpRequest);
        LocalDateTime now = LocalDateTime.now();

        User gateUser = userRepository.findByPhoneNumber(phone);
        assertRegisterPathAllowedForUser(gateUser, purpose, phone, "otp/createAndSend", acceptLanguage);

        enforceSendLimits(phone, ip, now, acceptLanguage);

        // Invalidate previous pending codes for this phone
        List<Otp> pending = otpRepository.findAllByPhoneNumberAndStatus(phone, OtpStatus.PENDING.name());
        pending.forEach(o -> o.setStatus(OtpStatus.FAIL.name()));
        otpRepository.saveAll(pending);

        User existingUser = userRepository.findByPhoneNumber(phone);
        Long userId = (existingUser != null
                && !UserStatus.DELETED.name().equalsIgnoreCase(existingUser.getStatus()))
                ? existingUser.getId() : null;

        String code = generateOtpCode();
        otpRepository.save(Otp.builder()
                .code(HashUtil.sha256Hex(code))
                .hashed(true)
                .status(OtpStatus.PENDING.name())
                .createdAt(now)
                .phoneNumber(phone)
                .userId(userId)
                .build());

        smsService.sendOtpToPhone(phone, code, acceptLanguage);
        recordSuccessfulSend(phone, ip, now);

        return AuthFlowResponse.builder()
                .authToken(authToken)
                .next(NEXT_VERIFY_OTP)
                .purpose(purpose)
                .message(EnumMessagesLangValues.OTP_SENT.getMessageByLang(acceptLanguage))
                .build();
    }

    @Transactional
    public AuthFlowResponse verify(NewOtpRequest request, String acceptLanguage) {
        if (request == null) {
            throw new HttpMessageConversionException(EnumMessagesLangValues.MISSING_BODY.getMessageByLang(acceptLanguage));
        }
        String authToken = requireAuthToken(request);
        assertNotConsumed(authToken);
        jwtService.assertPhoneAuthToken(authToken);

        String otpCode = request.getOtp() != null ? request.getOtp() : request.getOtpCode();
        if (otpCode == null || otpCode.isBlank()) {
            throw new AuthApiException("OTP_INCORRECT", "Incorrect verification code. Please try again.", HttpStatus.UNAUTHORIZED);
        }

        String phone = jwtService.extractPhoneFromAuthToken(authToken);
        String purposeRaw = jwtService.extractAndLogPurposeFromAuthToken(authToken);
        String purpose = stripStage(purposeRaw);
        LocalDateTime now = LocalDateTime.now();

        // Belt: block ACTIVE+PIN REGISTER even if SMS was somehow already requested.
        assertRegisterPathAllowedForUser(
                userRepository.findByPhoneNumber(phone), purpose, phone, "otp/verify", acceptLanguage);

        OtpRateLimit rate = otpRateLimitRepository.findByPhoneNumber(phone).orElse(null);
        if (rate != null && rate.getVerifyLockedUntil() != null && rate.getVerifyLockedUntil().isAfter(now)) {
            long rem = Math.max(1, java.time.Duration.between(now, rate.getVerifyLockedUntil()).getSeconds());
            throw new AuthApiException("OTP_VERIFY_LOCKED",
                    "You've reached the maximum number of attempts. Please try again when the restriction ends.",
                    HttpStatus.TOO_MANY_REQUESTS, rate.getVerifyLockedUntil(), rem);
        }

        Otp otpLast = otpRepository.findTopByPhoneNumberAndStatusOrderByCreatedAtDesc(phone, OtpStatus.PENDING.name());
        if (otpLast == null) {
            recordWrongVerifyOrThrow(phone);
            throw new AuthApiException("OTP_INCORRECT", "Incorrect verification code. Please try again.", HttpStatus.UNAUTHORIZED);
        }

        boolean match = Boolean.TRUE.equals(otpLast.getHashed())
                ? HashUtil.sha256Hex(otpCode).equals(otpLast.getCode())
                : otpCode.equals(otpLast.getCode());

        if (!match) {
            recordWrongVerifyOrThrow(phone);
            throw new AuthApiException("OTP_INCORRECT", "Incorrect verification code. Please try again.", HttpStatus.UNAUTHORIZED);
        }

        if (now.isAfter(otpLast.getCreatedAt().plusMinutes(otpExpirationMinutes))) {
            throw new AuthApiException("OTP_EXPIRED", "This code has expired. Please request a new one.", HttpStatus.BAD_REQUEST);
        }

        User user = userRepository.findByPhoneNumber(phone);
        if (user == null) {
            user = User.builder()
                    .phoneNumber(phone)
                    .createdAt(now)
                    .role(UserRoles.USER.name())
                    .status(UserStatus.OTP_VERIFIED.name())
                    .build();
            userRepository.save(user);
        } else if (!UserStatus.DELETED.name().equalsIgnoreCase(user.getStatus())) {
            user.setStatus(UserStatus.OTP_VERIFIED.name());
            userRepository.save(user);
        }

        if (user != null && !UserStatus.DELETED.name().equalsIgnoreCase(user.getStatus())) {
            Long userId = user.getId();
            List<Otp> phoneOtps = otpRepository.findAllByPhoneNumber(phone);
            for (Otp o : phoneOtps) {
                if (o.getUserId() == null) {
                    o.setUserId(userId);
                }
                if (OtpStatus.PENDING.name().equals(o.getStatus())) {
                    o.setStatus(o.getId().equals(otpLast.getId())
                            ? OtpStatus.SUCCESS.name() : OtpStatus.FAIL.name());
                }
            }
            otpRepository.saveAll(phoneOtps);
        } else {
            List<Otp> pending = otpRepository.findAllByPhoneNumberAndStatus(phone, OtpStatus.PENDING.name());
            pending.forEach(o -> o.setStatus(o.getId().equals(otpLast.getId())
                    ? OtpStatus.SUCCESS.name() : OtpStatus.FAIL.name()));
            otpRepository.saveAll(pending);
        }

        otpVerifyAttemptService.clearVerifyCounters(phone);

        String pinSetupToken = jwtService.generatePhoneAuthToken(phone, purpose + "|" + STAGE_SET_PIN, authTokenExpiration);
        return AuthFlowResponse.builder()
                .pinSetupToken(pinSetupToken)
                .next(NEXT_SET_PIN)
                .purpose(purpose)
                .message(EnumMessagesLangValues.OTP_VERIFIED_SUCCESS.getMessageByLang(acceptLanguage))
                .build();
    }

    @Transactional
    public PinSetResponse setPinCode(UserRequest request, String acceptLanguage) {
        if (request == null) {
            throw new HttpMessageConversionException(EnumMessagesLangValues.MISSING_BODY.getMessageByLang(acceptLanguage));
        }
        String pinSetupToken = requireAuthTokenBody(request.getPinSetupToken());
        assertNotConsumed(pinSetupToken);
        jwtService.assertPhoneAuthToken(pinSetupToken);

        String purposeRaw = jwtService.extractAndLogPurposeFromAuthToken(pinSetupToken);
        if (purposeRaw == null || !purposeRaw.contains(STAGE_SET_PIN)) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }
        String purpose = stripStage(purposeRaw);

        String pinCode = request.resolveCredential();
        PinValidator.validateNewUsersPin(pinCode);

        String phone = jwtService.extractPhoneFromAuthToken(pinSetupToken);
        User user = userRepository.findByPhoneNumber(phone);
        if (user == null) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }

        // Hard rail is on createAndSend/verify (ACTIVE+PIN + REGISTER).
        // Here status is usually OTP_VERIFIED after verify — do not block recovery setPin.

        user.setPinHash(argon2PasswordEncoder.encode(pinCode));
        user.setStatus(UserStatus.ACTIVE.name());
        user.setFailedPinAttempts(0);
        user.setLastFailedPinAt(null);
        user.setPinLockedUntil(null);
        // Must flush before revoke: @Modifying clearAutomatically would otherwise drop unflushed pin_hash
        userRepository.saveAndFlush(user);

        // Only forgot-PIN (RESET) may kill other devices. REGISTER / re-setPin must not.
        // keepDeviceId required — null previously revoked EVERY session (same-phone logout).
        if (PURPOSE_RESET.equals(purpose)) {
            String keepDeviceId = request.getDeviceId();
            if (keepDeviceId != null && !keepDeviceId.isBlank()) {
                int revoked = refreshTokenRepository.revokeAllExceptDevice(
                        user.getId(), keepDeviceId, LocalDateTime.now());
                authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "REVOKE_OTHERS",
                        user.getId(), phone, keepDeviceId, purpose, 200, null, null,
                        "setPin RESET revokeAllExceptDevice count=" + revoked);
            } else {
                log.warn("setPin RESET without deviceId; skip session revoke userId={}", user.getId());
                authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "REVOKE_SKIP",
                        user.getId(), phone, null, purpose, 200, null, null,
                        "setPin RESET without deviceId — sessions kept");
            }
        } else {
            authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "REVOKE_SKIP",
                    user.getId(), phone, request.getDeviceId(), purpose, 200, null, null,
                    "setPin purpose=" + purpose + " — no session revoke");
        }

        consumeAuthToken(pinSetupToken);
        final Long ensureUserId = user.getId();
        final String ensurePhone = user.getPhoneNumber();
        final String ensureRole = user.getRole();
        AfterCommit.run(() -> customerEnsurePublisher.publishForAppUser(
                ensureUserId, ensurePhone, ensureRole, acceptLanguage));
        return PinSetResponse.builder().status("PIN_SET").build();
    }

    @Transactional
    public UserResponse login(UserRequest request, String acceptLanguage) {
        if (request == null) {
            throw new HttpMessageConversionException(EnumMessagesLangValues.MISSING_BODY.getMessageByLang(acceptLanguage));
        }
        String phone = normalizePhone(request.getPhoneNumber());
        String pinCode = request.resolveCredential();
        if (phone == null || pinCode == null) {
            throw new AuthApiException("PIN_INCORRECT", "Incorrect PIN. Please try again.", HttpStatus.UNAUTHORIZED);
        }
        if (request.getDeviceId() == null || request.getDeviceId().isBlank()) {
            throw new AuthApiException("INVALID_TOKEN", "deviceId is required.", HttpStatus.BAD_REQUEST);
        }

        User user = userRepository.findByPhoneNumber(phone);
        if (user == null || UserStatus.DELETED.name().equalsIgnoreCase(user.getStatus())) {
            throw new AuthApiException("PIN_NOT_SET", "PIN is not set for this account.", HttpStatus.UNAUTHORIZED);
        }
        if (!UserStatus.ACTIVE.name().equalsIgnoreCase(user.getStatus())) {
            throw new AuthApiException("PIN_NOT_SET", "PIN is not set for this account.", HttpStatus.UNAUTHORIZED);
        }
        if (user.getPinHash() == null || user.getPinHash().isBlank()) {
            throw new AuthApiException("PIN_NOT_SET", "PIN is not set for this account.", HttpStatus.UNAUTHORIZED);
        }

        LocalDateTime now = LocalDateTime.now();
        pinAttemptService.clearExpiredLock(user.getId());
        user = userRepository.findById(user.getId()).orElseThrow();

        if (user.getPinLockedUntil() != null && user.getPinLockedUntil().isAfter(now)) {
            long rem = Math.max(1, java.time.Duration.between(now, user.getPinLockedUntil()).getSeconds());
            throw new PinLockedException(
                    "You've reached the maximum number of attempts. Please try again when the restriction ends.",
                    user.getPinLockedUntil(), rem);
        }

        if (!argon2PasswordEncoder.matches(pinCode, user.getPinHash())) {
            PinAttemptService.Result result = pinAttemptService.recordWrongPin(user.getId());
            if (result.locked()) {
                throw new PinLockedException(
                        "You've reached the maximum number of attempts. Please try again when the restriction ends.",
                        result.lockedUntil(), result.remainingSeconds());
            }
            throw new AuthApiException("PIN_INCORRECT", "Incorrect PIN. Please try again.", HttpStatus.UNAUTHORIZED);
        }

        pinAttemptService.clearFailureState(user.getId());

        String accessToken = jwtService.generateAccessToken(user, accessTokenExpiration);
        // Rotate only this device; other phones keep their sessions.
        int rotated = refreshTokenRepository.revokeByUserIdAndDeviceId(
                user.getId(), request.getDeviceId(), LocalDateTime.now());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(
                user, request.getDeviceId(), request.getPlatform());
        refreshToken.setUser(user);
        user.getRefreshTokens().add(refreshToken);
        userRepository.save(user);

        authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "LOGIN_ROTATE",
                user.getId(), phone, request.getDeviceId(), null, 200, null, null,
                "revokedSameDevice=" + rotated + " newRefreshId=" + refreshToken.getId()
                        + " platform=" + request.getPlatform());

        // Heal orphans (ACTIVE auth user, missing customers row) without waiting for add-details.
        final Long ensureUserId = user.getId();
        final String ensurePhone = user.getPhoneNumber();
        final String ensureRole = user.getRole();
        AfterCommit.run(() -> customerEnsurePublisher.publishForAppUser(
                ensureUserId, ensurePhone, ensureRole, acceptLanguage));

        return UserResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .role(user.getRole())
                .userId(user.getId())
                .name(user.getName())
                .surname(user.getSurname())
                .phoneNumber(user.getPhoneNumber())
                .message(EnumMessagesLangValues.LOGIN_SUCCESS.getMessageByLang(acceptLanguage))
                .build();
    }

    private void recordWrongVerifyOrThrow(String phone) {
        OtpVerifyAttemptService.Result result = otpVerifyAttemptService.recordWrongVerify(phone);
        if (result.locked()) {
            throw new AuthApiException("OTP_VERIFY_LOCKED",
                    "You've reached the maximum number of attempts. Please try again when the restriction ends.",
                    HttpStatus.TOO_MANY_REQUESTS, result.lockedUntil(), result.remainingSeconds());
        }
        throw new AuthApiException("OTP_INCORRECT", "Incorrect verification code. Please try again.", HttpStatus.UNAUTHORIZED);
    }

    private void enforceSendLimits(String phone, String ip, LocalDateTime now, String acceptLanguage) {
        // Expired locks must clear sendCount/window; otherwise unlock immediately re-locks for another full period.
        otpSendLockService.clearExpiredIpLock(ip);
        otpSendLockService.clearExpiredPhoneLock(phone);

        IpOtpRateLimit ipLimit = ipOtpRateLimitRepository.findByIpAddress(ip)
                .orElseGet(() -> IpOtpRateLimit.builder().ipAddress(ip).sendCount(0).build());
        if (ipLimit.getLockedUntil() != null && ipLimit.getLockedUntil().isAfter(now)) {
            long rem = Math.max(1, java.time.Duration.between(now, ipLimit.getLockedUntil()).getSeconds());
            throw new AuthApiException("LOGIN_LOCKED",
                    "Too many attempts. Please try again later.",
                    HttpStatus.TOO_MANY_REQUESTS, ipLimit.getLockedUntil(), rem);
        }

        OtpRateLimit phoneLimit = otpRateLimitRepository.findByPhoneNumber(phone)
                .orElseGet(() -> OtpRateLimit.builder().phoneNumber(phone).sendCount(0).verifyFailCount(0).build());

        if (phoneLimit.getPhoneLockedUntil() != null && phoneLimit.getPhoneLockedUntil().isAfter(now)) {
            long rem = Math.max(1, java.time.Duration.between(now, phoneLimit.getPhoneLockedUntil()).getSeconds());
            throw new AuthApiException("LOGIN_LOCKED",
                    EnumMessagesLangValues.OTP_RATE_LIMITED.getMessageByLang(acceptLanguage),
                    HttpStatus.TOO_MANY_REQUESTS, phoneLimit.getPhoneLockedUntil(), rem);
        }
        if (phoneLimit.getLastSentAt() != null
                && phoneLimit.getLastSentAt().isAfter(now.minusSeconds(resendCooldownSeconds))) {
            LocalDateTime until = phoneLimit.getLastSentAt().plusSeconds(resendCooldownSeconds);
            long rem = Math.max(1, java.time.Duration.between(now, until).getSeconds());
            throw new AuthApiException("LOGIN_LOCKED",
                    EnumMessagesLangValues.OTP_RESEND_COOLDOWN.getMessageByLang(acceptLanguage),
                    HttpStatus.TOO_MANY_REQUESTS, until, rem);
        }

        otpRateLimitRepository.save(phoneLimit);
        ipOtpRateLimitRepository.save(ipLimit);

        if (phoneLimit.getSendWindowStart() != null
                && !phoneLimit.getSendWindowStart().isBefore(now.minusMinutes(sendWindowMinutes))
                && phoneLimit.getSendCount() != null
                && phoneLimit.getSendCount() >= maxSendsPerWindow) {
            // REQUIRES_NEW so lock survives AuthApiException rollback on this method
            OtpSendLockService.Result lock = otpSendLockService.lockPhone(phone, phoneLockMinutes);
            throw new AuthApiException("LOGIN_LOCKED",
                    EnumMessagesLangValues.OTP_RATE_LIMITED.getMessageByLang(acceptLanguage),
                    HttpStatus.TOO_MANY_REQUESTS, lock.lockedUntil(), lock.remainingSeconds());
        }

        if (ipLimit.getSendWindowStart() != null
                && !ipLimit.getSendWindowStart().isBefore(now.minusMinutes(sendWindowMinutes))
                && ipLimit.getSendCount() != null
                && ipLimit.getSendCount() >= maxSendsPerWindow * 5) {
            OtpSendLockService.Result lock = otpSendLockService.lockIp(ip, ipLockHours);
            throw new AuthApiException("LOGIN_LOCKED",
                    "Too many attempts. Please try again later.",
                    HttpStatus.TOO_MANY_REQUESTS, lock.lockedUntil(), lock.remainingSeconds());
        }
    }

    private void recordSuccessfulSend(String phone, String ip, LocalDateTime now) {
        OtpRateLimit phoneLimit = otpRateLimitRepository.findByPhoneNumber(phone).orElseThrow();
        if (phoneLimit.getSendWindowStart() == null
                || phoneLimit.getSendWindowStart().isBefore(now.minusMinutes(sendWindowMinutes))) {
            phoneLimit.setSendWindowStart(now);
            phoneLimit.setSendCount(1);
        } else {
            phoneLimit.setSendCount((phoneLimit.getSendCount() == null ? 0 : phoneLimit.getSendCount()) + 1);
        }
        phoneLimit.setLastSentAt(now);
        phoneLimit.setLastIp(ip);
        otpRateLimitRepository.save(phoneLimit);

        IpOtpRateLimit ipLimit = ipOtpRateLimitRepository.findByIpAddress(ip).orElseThrow();
        if (ipLimit.getSendWindowStart() == null
                || ipLimit.getSendWindowStart().isBefore(now.minusMinutes(sendWindowMinutes))) {
            ipLimit.setSendWindowStart(now);
            ipLimit.setSendCount(1);
        } else {
            ipLimit.setSendCount((ipLimit.getSendCount() == null ? 0 : ipLimit.getSendCount()) + 1);
        }
        ipOtpRateLimitRepository.save(ipLimit);
    }

    private String requireAuthToken(NewOtpRequest request) {
        if (request == null || request.getAuthToken() == null || request.getAuthToken().isBlank()) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }
        return request.getAuthToken().trim();
    }

    private String requireAuthTokenBody(String authToken) {
        if (authToken == null || authToken.isBlank()) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }
        return authToken.trim();
    }

    private void assertNotConsumed(String authToken) {
        String hash = HashUtil.sha256Hex(stripBearer(authToken));
        if (consumedAuthTokenRepository.existsById(hash)) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }
    }

    private void consumeAuthToken(String authToken) {
        consumedAuthTokenRepository.save(ConsumedAuthToken.builder()
                .tokenHash(HashUtil.sha256Hex(stripBearer(authToken)))
                .consumedAt(LocalDateTime.now())
                .build());
    }

    private static String stripBearer(String token) {
        if (token == null) {
            return null;
        }
        String t = token.trim();
        return t.regionMatches(true, 0, "Bearer ", 0, 7) ? t.substring(7).trim() : t;
    }

    private static String stripStage(String purposeRaw) {
        if (purposeRaw == null) {
            return PURPOSE_REGISTER;
        }
        int idx = purposeRaw.indexOf('|');
        return idx >= 0 ? purposeRaw.substring(0, idx) : purposeRaw;
    }

    private static String generateOtpCode() {
        return String.valueOf(100000 + new Random().nextInt(900000));
    }

    /** Basic AZ mobile normalize: 070... → +99470... ; reject obviously bad. */
    private static String normalizePhone(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String p = raw.trim().replace(" ", "").replace("-", "");
        if (p.matches("0\\d{9}")) {
            p = "+994" + p.substring(1);
        }
        if (!p.matches("\\+994\\d{9}")) {
            return null;
        }
        return p;
    }

    private static String resolveClientIp(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr() == null ? "unknown" : request.getRemoteAddr();
    }
}
