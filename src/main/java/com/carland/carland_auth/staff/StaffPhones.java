package com.carland.carland_auth.staff;

import com.carland.carland_auth.enums.EnumMessagesLangValues;
import com.carland.carland_auth.exceptions.AuthApiException;
import org.springframework.http.HttpStatus;

import java.util.Set;

/**
 * Staff login/forgot phones must be +994 + one of the eight AZ mobile prefixes.
 * Owner {@code PhoneNumbers.normalize} is unchanged (0-prefix still allowed there).
 */
public final class StaffPhones {

    static final Set<String> OPERATORS = Set.of("10", "50", "51", "55", "60", "70", "77", "99");

    private StaffPhones() {
    }

    /**
     * Blank → null (caller may use email instead). Otherwise +994XXXXXXXXX or throws 400.
     */
    public static String requireLoginPhone(String raw, String lang) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String compact = raw.trim().replace(" ", "").replace("-", "");
        if (!compact.startsWith("+994")) {
            throw new AuthApiException("INVALID_PHONE",
                    EnumMessagesLangValues.STAFF_PHONE_MUST_START_994.getMessageByLang(lang),
                    HttpStatus.BAD_REQUEST);
        }
        String rest = compact.substring(4);
        if (rest.length() >= 2 && !OPERATORS.contains(rest.substring(0, 2))) {
            throw new AuthApiException("UNKNOWN_OPERATOR",
                    EnumMessagesLangValues.STAFF_UNKNOWN_OPERATOR.getMessageByLang(lang),
                    HttpStatus.BAD_REQUEST);
        }
        if (!rest.matches("\\d{9}")) {
            throw new AuthApiException("INVALID_PHONE",
                    EnumMessagesLangValues.STAFF_PHONE_INVALID.getMessageByLang(lang),
                    HttpStatus.BAD_REQUEST);
        }
        return "+994" + rest;
    }

    /** After owner-style normalize (+994 + 9 digits). */
    public static void assertAllowedOperator(String plus994, String lang) {
        if (plus994 == null || plus994.length() < 6) {
            throw new AuthApiException("INVALID_PHONE",
                    EnumMessagesLangValues.STAFF_PHONE_INVALID.getMessageByLang(lang),
                    HttpStatus.BAD_REQUEST);
        }
        String op = plus994.substring(4, 6);
        if (!OPERATORS.contains(op)) {
            throw new AuthApiException("UNKNOWN_OPERATOR",
                    EnumMessagesLangValues.STAFF_UNKNOWN_OPERATOR.getMessageByLang(lang),
                    HttpStatus.BAD_REQUEST);
        }
    }
}
