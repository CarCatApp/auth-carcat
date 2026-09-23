package com.carland.carland_auth.jwt;

import com.carland.carland_auth.entity.User;
import com.carland.carland_auth.exceptions.AuthApiException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.function.Function;

@Service
@Slf4j
public class JWTService {

    @Value("${access.token.secret-key}")
    private String accessTokenSecretKey;

    @Value("${authentication.token.secret-key}")
    private String authenticationTokenSecretKey;

    @Value("${refresh.token.secret-key}")
    private String refreshTokenSecretKey;

    @Value("${carland.issuer.key}")
    private String issuerKey;


    public String generateAccessToken(User user, Long expirationTime) {
        boolean mustChange = user.getStatus() != null
                && "INVITED".equalsIgnoreCase(user.getStatus());
        return generateAccessToken(user, expirationTime, mustChange);
    }

    public String generateAccessToken(User user, Long expirationTime, boolean mustChangePassword) {
        return Jwts.builder()
                .subject(user.getPhoneNumber())
                .claim("userId", user.getId())
                .claim("role", user.getRole())
                .claim("name", user.getName())
                .claim("surname", user.getSurname())
                .claim("mustChangePassword", mustChangePassword)
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(expirationTime)))
                .signWith(getSignKey(accessTokenSecretKey))
                .issuer(issuerKey)
                .compact();
    }

    public String generateRefreshToken(User user, Long expirationTime) {
        return Jwts.builder()
                .subject(user.getPhoneNumber())
                .claim("userId", user.getId())
                .claim("role", user.getRole())
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(expirationTime)))
                .signWith(getSignKey(refreshTokenSecretKey))
                .issuer(issuerKey)
                .compact();
    }

    public String generateAuthenticationToken(User user, Long expirationTime) {
        return Jwts.builder()
                .claim("userId", user.getId())
                .claim("type", "AUTHENTICATION")
                .subject("user-authentication")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(expirationTime)))
                .signWith(getSignKey(authenticationTokenSecretKey))
                .compact();
    }

    /**
     * New-users flow authToken (user may not exist yet). Carries phone + purpose.
     */
    public String generatePhoneAuthToken(String phoneNumber, String purpose, Long expirationTime) {
        return Jwts.builder()
                .claim("phoneNumber", phoneNumber)
                .claim("purpose", purpose == null ? "REGISTER" : purpose.toUpperCase())
                .claim("type", "AUTH_FLOW")
                .subject("auth-flow")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(expirationTime)))
                .signWith(getSignKey(authenticationTokenSecretKey))
                .compact();
    }

    public String generateStaffResetToken(User user, Long expirationTime) {
        return Jwts.builder()
                .claim("userId", user.getId())
                .claim("phoneNumber", user.getPhoneNumber())
                .claim("purpose", "STAFF_PASSWORD_RESET")
                .claim("type", "AUTH_FLOW")
                .subject("staff-password-reset")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(expirationTime)))
                .signWith(getSignKey(authenticationTokenSecretKey))
                .compact();
    }

    public void assertStaffResetToken(String token) {
        assertPhoneAuthToken(token);
        String purpose = extractPurposeFromAuthToken(token);
        if (!"STAFF_PASSWORD_RESET".equalsIgnoreCase(purpose)) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }
    }

    public String extractPhoneFromAuthToken(String token) {
        return extractClaim(stripBearer(token), claims -> claims.get("phoneNumber", String.class), authenticationTokenSecretKey);
    }

    public String extractPurposeFromAuthToken(String token) {
        return extractClaim(stripBearer(token), claims -> claims.get("purpose", String.class), authenticationTokenSecretKey);
    }

    public boolean isPhoneAuthTokenValid(String token) {
        try {
            assertPhoneAuthToken(token);
            return true;
        } catch (AuthApiException ex) {
            return false;
        }
    }

    /**
     * Validates NewUsers authToken. Throws AUTH_TOKEN_EXPIRED or INVALID_TOKEN (401).
     */
    public void assertPhoneAuthToken(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }
        String raw = stripBearer(token);
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSignKey(authenticationTokenSecretKey))
                    .build()
                    .parseSignedClaims(raw)
                    .getPayload();
            if (!"AUTH_FLOW".equals(claims.get("type", String.class))) {
                throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
            }
            if (claims.getExpiration() != null && claims.getExpiration().before(new Date())) {
                throw new AuthApiException("AUTH_TOKEN_EXPIRED", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
            }
        } catch (AuthApiException ex) {
            throw ex;
        } catch (ExpiredJwtException ex) {
            throw new AuthApiException("AUTH_TOKEN_EXPIRED", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        } catch (Exception ex) {
            throw new AuthApiException("INVALID_TOKEN", "Your session expired. Please start again.", HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Extracts purpose claim and logs it (PO/debug). Returns raw claim (may include |SET_PIN).
     */
    public String extractAndLogPurposeFromAuthToken(String token) {
        String purpose = extractPurposeFromAuthToken(token);
        log.info("purpose extracted from JWT: {}", purpose);
        return purpose;
    }

    private String stripBearer(String token) {
        if (token == null) {
            return null;
        }
        String t = token.trim();
        return t.regionMatches(true, 0, "Bearer ", 0, 7) ? t.substring(7).trim() : t;
    }


    public Long extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", Long.class), accessTokenSecretKey);
    }

    public Long extractUserIdFromRefreshToken(String token) {
        return extractClaim(stripBearer(token), claims -> claims.get("userId", Long.class), refreshTokenSecretKey);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject, accessTokenSecretKey);
    }


    public Long extractUserIdFromAuthenticationToken(String token) {
        return extractClaim(stripBearer(token), claims -> {
            Object value = claims.get("userId");
            if (value instanceof Number number) {
                return number.longValue();
            }
            return null;
        }, authenticationTokenSecretKey);
    }


    public boolean isAccessTokenValid(String token) {
        return !isTokenExpired(token, accessTokenSecretKey);
    }

    public boolean isAuthenticationTokenValid(String token) {
        return !isTokenExpired(stripBearer(token), authenticationTokenSecretKey);
    }

    public boolean isRefreshTokenValid(String token) {
        return !isTokenExpired(stripBearer(token), refreshTokenSecretKey);
    }


    private boolean isTokenExpired(String token, String key) {
        try {
            Date exp = extractClaim(token, Claims::getExpiration, key);
            return exp.before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }


    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver, String key) {
        Claims claims = Jwts.parser()
                .verifyWith(getSignKey(key))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claimsResolver.apply(claims);
    }

    private SecretKey getSignKey(String key) {
        return Keys.hmacShaKeyFor(key.getBytes());
    }

    public String extractUserRoleFromAuthenticationToken(String token) {
        return extractClaim(token.substring(7).trim(), claims -> claims.get("role", String.class), authenticationTokenSecretKey);
    }

    public String extractUserRoleFromAccessToken(String token) {
        return extractClaim(token.substring(7).trim(), claims -> claims.get("role", String.class), accessTokenSecretKey);
    }

    public Boolean extractMustChangePassword(String token) {
        String raw = stripBearer(token);
        Boolean value = extractClaim(raw, claims -> claims.get("mustChangePassword", Boolean.class), accessTokenSecretKey);
        return Boolean.TRUE.equals(value);
    }
}
