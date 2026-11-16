package com.carland.carland_auth.service;

import com.carland.carland_auth.entity.Log;
import com.carland.carland_auth.repository.LogRepository;
import com.carland.carland_auth.util.LogBodySanitizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.UUID;

/**
 * Persists auth/session diagnostic rows in {@link Log} (+ slf4j).
 * REQUIRES_NEW so rows survive business TX rollback (failed PIN/OTP still recorded).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthFlowLogService {

    public static final String ATTR_TRACE_ID = "authFlowTraceId";

    public static final String SRC_HTTP = "HTTP";
    public static final String SRC_STEP = "STEP";

    private final LogRepository logRepository;
    private final ObjectMapper objectMapper;
    private final LogBodySanitizer sanitizer;

    public String ensureTraceId(HttpServletRequest request) {
        Object existing = request.getAttribute(ATTR_TRACE_ID);
        if (existing instanceof String s && !s.isBlank()) {
            return s;
        }
        String header = request.getHeader("X-Request-Id");
        String traceId = (header != null && !header.isBlank())
                ? header.trim()
                : UUID.randomUUID().toString().replace("-", "");
        request.setAttribute(ATTR_TRACE_ID, traceId);
        return traceId;
    }

    public String currentTraceId(HttpServletRequest request) {
        Object existing = request.getAttribute(ATTR_TRACE_ID);
        return existing instanceof String s ? s : null;
    }

    /** Trace from current HTTP request (filter sets it); null outside web request. */
    public String traceIdOrNull() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (!(attrs instanceof ServletRequestAttributes servletAttrs)) {
            return null;
        }
        return currentTraceId(servletAttrs.getRequest());
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordHttp(ContentCachingRequestWrapper request,
                           ContentCachingResponseWrapper response,
                           String action) {
        try {
            String traceId = ensureTraceId(request);
            String rawReq = bodyOf(request.getContentAsByteArray(), request.getCharacterEncoding());
            String rawRes = bodyOf(response.getContentAsByteArray(), response.getCharacterEncoding());
            String safeReq = sanitizer.sanitizeJsonOrText(rawReq);
            String safeRes = sanitizer.sanitizeJsonOrText(rawRes);

            String phone = extractField(safeReq, "phoneNumber");
            String deviceId = firstNonBlank(
                    extractField(safeReq, "deviceId"),
                    extractField(safeReq, "deviceToken"));
            String purpose = extractField(safeReq, "purpose");
            if (purpose == null) {
                purpose = extractField(safeRes, "purpose");
            }
            String userId = extractField(safeRes, "userId");
            String errorCode = extractField(safeRes, "error");
            String errorMessage = extractField(safeRes, "message");
            int status = response.getStatus();

            Log row = Log.builder()
                    .createdAt(LocalDateTime.now())
                    .traceId(traceId)
                    .source(SRC_HTTP)
                    .action(action)
                    .userId(userId)
                    .phoneNumber(phone)
                    .deviceId(sanitizer.shortDeviceId(deviceId))
                    .purpose(purpose)
                    .httpMethod(request.getMethod())
                    .path(pathOf(request))
                    .httpStatus(status)
                    .errorCode(status >= 400 ? errorCode : null)
                    .errorMessage(status >= 400 ? truncate(errorMessage, 1024) : null)
                    .requestBody(truncate(safeReq, 8000))
                    .responseBody(truncate(safeRes, 8000))
                    .detail(null)
                    .clientIp(clientIp(request))
                    .build();
            logRepository.save(row);

            log.info("AUTH_FLOW HTTP trace={} action={} status={} phone={} device={} path={} err={}",
                    traceId, action, status, phone, sanitizer.shortDeviceId(deviceId),
                    pathOf(request), status >= 400 ? errorCode : "-");
        } catch (Exception ex) {
            log.warn("AUTH_FLOW HTTP persist failed: {}", ex.getMessage());
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordStep(String traceId,
                           String action,
                           Long userId,
                           String phoneNumber,
                           String deviceId,
                           String purpose,
                           Integer httpStatus,
                           String errorCode,
                           String errorMessage,
                           String detail) {
        try {
            Log row = Log.builder()
                    .createdAt(LocalDateTime.now())
                    .traceId(traceId)
                    .source(SRC_STEP)
                    .action(action)
                    .userId(userId == null ? null : String.valueOf(userId))
                    .phoneNumber(phoneNumber)
                    .deviceId(sanitizer.shortDeviceId(deviceId))
                    .purpose(purpose)
                    .httpMethod(null)
                    .path(null)
                    .httpStatus(httpStatus)
                    .errorCode(errorCode)
                    .errorMessage(truncate(errorMessage, 1024))
                    .requestBody(null)
                    .responseBody(null)
                    .detail(truncate(detail, 4000))
                    .clientIp(null)
                    .build();
            logRepository.save(row);

            log.info("AUTH_FLOW STEP trace={} action={} userId={} phone={} device={} status={} err={} detail={}",
                    traceId, action, userId, phoneNumber, sanitizer.shortDeviceId(deviceId),
                    httpStatus, errorCode, detail);
        } catch (Exception ex) {
            log.warn("AUTH_FLOW STEP persist failed: {}", ex.getMessage());
        }
    }

    private static String pathOf(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String qs = request.getQueryString();
        return qs == null || qs.isBlank() ? uri : uri + "?" + qs;
    }

    private static String clientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private static String bodyOf(byte[] bytes, String encoding) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        try {
            String enc = encoding != null ? encoding : StandardCharsets.UTF_8.name();
            return new String(bytes, enc);
        } catch (Exception e) {
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    private String extractField(String json, String field) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            JsonNode node = objectMapper.readTree(json);
            JsonNode v = node.get(field);
            if (v == null || v.isNull()) {
                return null;
            }
            String s = v.asText();
            return s == null || s.isBlank() ? null : s;
        } catch (Exception e) {
            return null;
        }
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        if (b != null && !b.isBlank()) {
            return b;
        }
        return null;
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return null;
        }
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    public static String actionForPath(String method, String path) {
        if (path == null) {
            return "UNKNOWN";
        }
        String p = path.toLowerCase(Locale.ROOT);
        if (p.contains("/newusers/auth")) {
            return "AUTH";
        }
        if (p.contains("/otp/createandsend")) {
            return "OTP_SEND";
        }
        if (p.contains("/otp/verify")) {
            return "OTP_VERIFY";
        }
        if (p.contains("/setpincode")) {
            return "SET_PIN";
        }
        if (p.contains("/newusers/login") || p.endsWith("/users/login")) {
            return "LOGIN";
        }
        if (p.contains("/users/refresh")) {
            return "REFRESH";
        }
        return method + " " + path;
    }
}
