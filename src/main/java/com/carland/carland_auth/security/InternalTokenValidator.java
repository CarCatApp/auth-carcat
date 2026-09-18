package com.carland.carland_auth.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * tr: Auth internal staff provision için X-Internal-Token doğrulaması.
 * en: Validates X-Internal-Token for auth internal staff provision.
 */
@Component
public class InternalTokenValidator {

    public static final String HEADER_NAME = "X-Internal-Token";

    private final String expectedToken;

    public InternalTokenValidator(@Value("${carland.internal-token:}") String expectedToken) {
        this.expectedToken = expectedToken;
    }

    public boolean isConfigured() {
        return StringUtils.hasText(expectedToken);
    }

    public boolean matches(HttpServletRequest request) {
        if (!isConfigured()) {
            return false;
        }
        String provided = request.getHeader(HEADER_NAME);
        if (!StringUtils.hasText(provided)) {
            return false;
        }
        return MessageDigest.isEqual(
                provided.getBytes(StandardCharsets.UTF_8),
                expectedToken.getBytes(StandardCharsets.UTF_8)
        );
    }
}
