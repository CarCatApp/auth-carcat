package com.carland.carland_auth.service.impl;


import com.carland.carland_auth.dto.request.UserRequest;
import com.carland.carland_auth.dto.response.AuthenticationResponse;
import com.carland.carland_auth.dto.response.UserResponse;
import com.carland.carland_auth.entity.RefreshToken;
import com.carland.carland_auth.entity.User;
import com.carland.carland_auth.enums.EnumMessagesLangValues;
import com.carland.carland_auth.feign.CarlandFeign;
import com.carland.carland_auth.enums.UserStatus;
import com.carland.carland_auth.exceptions.*;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.messaging.CustomerEnsurePublisher;
import com.carland.carland_auth.repository.RefreshTokenRepository;
import com.carland.carland_auth.repository.UserRepository;
import com.carland.carland_auth.service.AuthFlowLogService;
import com.carland.carland_auth.service.PinAttemptService;
import com.carland.carland_auth.service.interfaces.OtpService;
import com.carland.carland_auth.service.interfaces.RefreshTokenService;
import com.carland.carland_auth.service.interfaces.UserService;
import com.carland.carland_auth.util.AfterCommit;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    @Value("${access.token.expiration}")
    private Long ACCESS_TOKEN_EXPIRATION;

    @Value("${authentication.token.expiration}")
    private Long AUTHENTICATION_TOKEN_EXPIRATION;

    private final BCryptPasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JWTService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthFlowLogService authFlowLogService;
    private final OtpService otpService;
    private final PinAttemptService pinAttemptService;
    private final CarlandFeign carlandFeign;
    private final CustomerEnsurePublisher customerEnsurePublisher;

    @Value("${carland.internal-token:}")
    private String internalToken;

    @Transactional
    @Override
    public AuthenticationResponse authenticate(UserRequest request, String role, String acceptLanguage) {
        if (request == null || role == null) {
            log.info("missing body error");
            throw new HttpMessageConversionException(EnumMessagesLangValues.MISSING_BODY
                    .getMessageByLang(acceptLanguage));
        }
        log.info("request from controller for authenticate : {}", request);

        if (request.getPhoneNumber() == null) {
            log.info("missing field error");
            throw new MissingFieldException(EnumMessagesLangValues.MISSING_FIELDS.getMessageByLang(acceptLanguage));
        }


        User existingUser = userRepository.findByPhoneNumber(request.getPhoneNumber());
        if (existingUser != null) {
            if (UserStatus.ACTIVE.name().equalsIgnoreCase(existingUser.getStatus())) {
                log.info("user already exists");
                throw new UsernameAlreadyExistException(EnumMessagesLangValues.USERNAME_ALREADY_EXISTS
                        .getMessageByLang(acceptLanguage));
            }

            existingUser.setCreatedAt(LocalDateTime.now());
            existingUser.setStatus(UserStatus.OTP_PENDING.name());
            existingUser.setRole(role.toUpperCase());
            userRepository.save(existingUser);
            log.info("updated existing user: {}", existingUser);
            String authenticationJwt = jwtService.generateAuthenticationToken(existingUser, AUTHENTICATION_TOKEN_EXPIRATION);
            return AuthenticationResponse.ofToken(
                    authenticationJwt,
                    EnumMessagesLangValues.REGISTER_SUCCESS_UPDATED.getMessageByLang(acceptLanguage));
        }
        User newUser = User.builder()
                .phoneNumber(request.getPhoneNumber())
                .pin(UUID.randomUUID().toString())
                .name(request.getName())
                .surname(request.getSurname())
                .createdAt(LocalDateTime.now())
                .role(role.toUpperCase())
                .status(UserStatus.OTP_PENDING.name())
                .build();
        userRepository.save(newUser);
        log.info("new user {}", newUser);
        String authenticationJwt = jwtService.generateAuthenticationToken(newUser, AUTHENTICATION_TOKEN_EXPIRATION);
        return AuthenticationResponse.ofToken(
                authenticationJwt,
                EnumMessagesLangValues.REGISTER_SUCCESS.getMessageByLang(acceptLanguage));
    }


    @Override
    @Transactional
    public UserResponse login(UserRequest request, String acceptLanguage) {
        if (request == null) {
            log.info("missing body error");
            throw new HttpMessageConversionException(EnumMessagesLangValues.MISSING_BODY.getMessageByLang(acceptLanguage));
        }
        log.info("request from controller for login : {}", request);
        String credential = request.resolveCredential();
        if (request.getPhoneNumber() == null || credential == null) {
            log.info("missing field error");
            throw new MissingFieldException(EnumMessagesLangValues.MISSING_USER_FIELDS.getMessageByLang(acceptLanguage));
        }

        User user = userRepository.findByPhoneNumberAndStatus(request.getPhoneNumber(), UserStatus.ACTIVE.name());
        log.info("user from repository  : {}", user);
        if (user == null) {
            log.info("user not found error");
            throw new UserNotFoundException(EnumMessagesLangValues.USER_NOT_FOUND.getMessageByLang(acceptLanguage));
        }

        LocalDateTime now = LocalDateTime.now();
        pinAttemptService.clearExpiredLock(user.getId());
        user = userRepository.findById(user.getId()).orElseThrow();

        if (user.getPinLockedUntil() != null && user.getPinLockedUntil().isAfter(now)) {
            long remainingSeconds = Math.max(1, java.time.Duration.between(now, user.getPinLockedUntil()).getSeconds());
            throw new PinLockedException(
                    EnumMessagesLangValues.PIN_LOCKED.getMessageByLang(acceptLanguage),
                    user.getPinLockedUntil(),
                    remainingSeconds);
        }

        if (!passwordEncoder.matches(credential, user.getPin())) {
            PinAttemptService.Result result = pinAttemptService.recordWrongPin(user.getId());
            if (result.locked()) {
                throw new PinLockedException(
                        EnumMessagesLangValues.PIN_LOCKED.getMessageByLang(acceptLanguage),
                        result.lockedUntil(),
                        result.remainingSeconds());
            }
            throw new WrongPasswordException(EnumMessagesLangValues.WRONG_PASSWORD.getMessageByLang(acceptLanguage));
        }

        pinAttemptService.clearFailureState(user.getId());

        String accessTokenJWT = jwtService.generateAccessToken(user, ACCESS_TOKEN_EXPIRATION);

        String deviceId = request.getDeviceId();
        int rotated = 0;
        if (deviceId != null && !deviceId.isBlank()) {
            // clearAutomatically — avoid lazy user.refreshTokens after this.
            rotated = refreshTokenRepository.revokeByUserIdAndDeviceId(user.getId(), deviceId, LocalDateTime.now());
        }

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(
                user, deviceId, request.getPlatform());
        refreshToken.setUser(user);
        refreshToken = refreshTokenRepository.save(refreshToken);

        authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "LOGIN_ROTATE",
                user.getId(), user.getPhoneNumber(), deviceId, null, 200, null, null,
                "legacyLogin revokedSameDevice=" + rotated + " newRefreshId=" + refreshToken.getId());

        return UserResponse.builder()
                .accessToken(accessTokenJWT)
                .refreshToken(refreshToken.getToken())
                .role(user.getRole())
                .userId(user.getId())
                .name(user.getName())
                .surname(user.getSurname())
                .phoneNumber(user.getPhoneNumber())
                .message(EnumMessagesLangValues.LOGIN_SUCCESS.getMessageByLang(acceptLanguage))
                .build();
    }

    @Override
    public UserResponse refresh(Long userId, String refreshToken, String acceptLanguage) {

        if (userId == null) {
            log.info("missing  field error ");
            authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "REFRESH_REJECT",
                    null, null, null, null, 400, "MISSING_USER_ID", "userId null", "refresh missing userId");
            throw new MissingFieldException(EnumMessagesLangValues.MISSING_USER_ID.getMessageByLang(acceptLanguage));
        }
        User user = userRepository.findByIdAndStatus(userId, UserStatus.ACTIVE.name());
        if (user == null) {
            log.info("user not found error");
            authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "REFRESH_REJECT",
                    userId, null, null, null, 404, "USER_NOT_FOUND", "user not ACTIVE",
                    "refresh userId not found or not ACTIVE");
            throw new UserNotFoundException(EnumMessagesLangValues.USER_NOT_FOUND.getMessageByLang(acceptLanguage));
        }

        String raw = refreshToken != null && refreshToken.startsWith("Bearer ")
                ? refreshToken.substring(7)
                : refreshToken;
        if (raw == null || raw.isBlank()) {
            authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "REFRESH_REJECT",
                    userId, user.getPhoneNumber(), null, null, 401, "REFRESH_TOKEN_NOT_FOUND",
                    "blank token", "refresh Authorization blank");
            throw new RefreshTokenNotSetException(EnumMessagesLangValues.REFRESH_TOKEN_NOT_FOUND
                    .getMessageByLang(acceptLanguage));
        }

        // Accept any active token for this user (multi-device); latest-only caused same-phone logout.
        RefreshToken refreshTokenEntity =
                refreshTokenRepository.findByUserIdAndTokenAndRevokedAtIsNull(userId, raw);
        if (refreshTokenEntity == null) {
            RefreshToken any = refreshTokenRepository.findByUserIdAndToken(userId, raw);
            String reason;
            if (any == null) {
                reason = "token_unknown_for_user";
            } else if (any.getRevokedAt() != null) {
                reason = "token_revoked_at=" + any.getRevokedAt() + " deviceId=" + any.getDeviceId();
            } else {
                reason = "token_row_unusable";
            }
            log.info("refresh rejected userId={} reason={}", userId, reason);
            authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "REFRESH_REJECT",
                    userId, user.getPhoneNumber(),
                    any == null ? null : any.getDeviceId(),
                    null, 401, "REFRESH_TOKEN_NOT_FOUND", reason, reason);
            throw new RefreshTokenNotSetException(EnumMessagesLangValues.REFRESH_TOKEN_NOT_FOUND
                    .getMessageByLang(acceptLanguage));
        }

        String accessTokenJWT = jwtService.generateAccessToken(user, ACCESS_TOKEN_EXPIRATION);

        authFlowLogService.recordStep(authFlowLogService.traceIdOrNull(), "REFRESH_OK",
                userId, user.getPhoneNumber(), refreshTokenEntity.getDeviceId(), null, 200, null, null,
                "refreshId=" + refreshTokenEntity.getId() + " createdAt=" + refreshTokenEntity.getCreatedAt());

        return UserResponse.builder()
                .refreshToken(refreshTokenEntity.getToken())
                .accessToken(accessTokenJWT)
                .role(user.getRole())
                .name(user.getName())
                .surname(user.getSurname())
                .phoneNumber(user.getPhoneNumber())
                .message(EnumMessagesLangValues.REFRESH_TOKEN_SUCCESS.getMessageByLang(acceptLanguage))
                .build();
    }

    @Override
    @Transactional
    public UserResponse setPin(UserRequest userRequest, Long userId, String acceptLanguage) {

        User user = userRepository.findById(userId).orElseThrow(() ->
                new UserNotFoundException(EnumMessagesLangValues.USER_NOT_FOUND.getMessageByLang(acceptLanguage)));

        if (!user.getStatus().equals(UserStatus.OTP_VERIFIED.name())) {
            throw new InvalidStatusException(EnumMessagesLangValues.INVALID_USER_STATUS.getMessageByLang(acceptLanguage));
        }
        // Legacy setPassword: free-form password (no 4-digit PIN rules). Stored in password column.
        String credential = userRequest.resolveCredential();
        if (credential == null || credential.isBlank()) {
            throw new MissingFieldException(EnumMessagesLangValues.MISSING_USER_FIELDS.getMessageByLang(acceptLanguage));
        }
        user.setPin(passwordEncoder.encode(credential));
        user.setStatus(UserStatus.ACTIVE.name());

        AfterCommit.run(() -> customerEnsurePublisher.publishForAppUser(
                user.getId(), user.getPhoneNumber(), user.getRole(), acceptLanguage));

        return UserResponse.builder()
                .message(EnumMessagesLangValues.PASSWORD_SET_SUCCESS.getMessageByLang(acceptLanguage))
                .role(user.getRole())
                .name(user.getName())
                .surname(user.getSurname())
                .phoneNumber(user.getPhoneNumber())
                .build();
    }

    @Override
    public AuthenticationResponse updatePin(UserRequest userRequest, String acceptLanguage) {
        if (userRequest.getPhoneNumber() == null) {
            throw new MissingFieldException(EnumMessagesLangValues.MISSING_PHONE_NUMBER.getMessageByLang(acceptLanguage));
        }

        User user = userRepository.findByPhoneNumber(userRequest.getPhoneNumber());

        if (user == null || user.getStatus().equalsIgnoreCase(UserStatus.DELETED.name())) {
            throw new UserNotFoundException(EnumMessagesLangValues.USER_NOT_FOUND.getMessageByLang(acceptLanguage));
        }

        otpService.createOtp(user.getId(), acceptLanguage);
        String authenticationJwt = jwtService.generateAuthenticationToken(user, AUTHENTICATION_TOKEN_EXPIRATION);
        return AuthenticationResponse.ofToken(
                authenticationJwt,
                EnumMessagesLangValues.OTP_SENT.getMessageByLang(acceptLanguage));
    }

    @Override
    public UserResponse deleteUser(Long userId, String acceptLanguage) {

        User user = userRepository.findById(userId).orElseThrow(() ->
                new UserNotFoundException(EnumMessagesLangValues.USER_NOT_FOUND.getMessageByLang(acceptLanguage)));

        user.setStatus(UserStatus.DELETED.name());
        userRepository.save(user);
        anonymizeClientEvents(userId);
        return UserResponse.builder()
                .message(EnumMessagesLangValues.USER_SUCCESSFULLY_DELETED.getMessageByLang(acceptLanguage))
                .build();
    }

    /**
     * tr: Hesab silindikdən sonra crash sətirlərində userId boşalır. Servis əlçatan deyilsə silmə dayanmır.
     * en: After the account is deleted, crash rows lose userId. A service failure does not block deletion.
     */
    private void anonymizeClientEvents(Long userId) {
        if (internalToken == null || internalToken.isBlank()) {
            log.error("client-events anonymize skipped, internal token empty, userId={}", userId);
            return;
        }
        try {
            carlandFeign.anonymizeClientEvents(internalToken, userId);
        } catch (RuntimeException ex) {
            log.error("client-events anonymize failed userId={} type={}", userId, ex.getClass().getSimpleName());
        }
    }

}

