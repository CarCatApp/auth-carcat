package com.carland.carland_auth.staff;

import com.carland.carland_auth.exceptions.AuthApiException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * HMAC-SHA256 of the staff OTP. The plaintext code is never stored.
 */
@Component
public class StaffOtpHasher {

    private static final String HMAC = "HmacSHA256";

    @Value("${staff.otp.pepper:}")
    private String pepper;

    @Value("${access.token.secret-key:}")
    private String accessTokenSecret;

    public String hash(String code) {
        String key = pepper != null && !pepper.isBlank() ? pepper : accessTokenSecret;
        if (key == null || key.isBlank()) {
            throw new AuthApiException("OTP_PEPPER_MISSING",
                    "STAFF_OTP_PEPPER is not set", HttpStatus.SERVICE_UNAVAILABLE);
        }
        if (code == null || code.isBlank()) {
            throw new AuthApiException("MISSING_FIELD", "otp is required", HttpStatus.BAD_REQUEST);
        }
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), HMAC));
            byte[] raw = mac.doFinal(code.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(raw);
        } catch (AuthApiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new AuthApiException("OTP_HASH_FAILED", "OTP could not be protected", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public boolean matches(String code, String storedHash) {
        if (code == null || storedHash == null || storedHash.length() != 64) {
            return false;
        }
        byte[] actual;
        byte[] expected;
        try {
            actual = HexFormat.of().parseHex(hash(code));
            expected = HexFormat.of().parseHex(storedHash);
        } catch (AuthApiException ex) {
            throw ex;
        } catch (Exception ex) {
            return false;
        }
        return MessageDigest.isEqual(actual, expected);
    }
}
