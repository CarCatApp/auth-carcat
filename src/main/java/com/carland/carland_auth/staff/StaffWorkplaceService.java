package com.carland.carland_auth.staff;

import com.carland.carland_auth.entity.StaffAccount;
import com.carland.carland_auth.enums.EnumMessagesLangValues;
import com.carland.carland_auth.exceptions.AuthApiException;
import com.carland.carland_auth.exceptions.UserNotFoundException;
import com.carland.carland_auth.feign.CarlandBookingFeign;
import com.carland.carland_auth.staff.dto.StaffLoginGateResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Login and password change ask carland whether the place is still open.
 * Hand-close is stored on the staff account and is not cleared by a place reopen.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class StaffWorkplaceService {

    static final String ALLOWED = "ALLOWED";
    static final String SUSPENDED = "SUSPENDED";
    static final String ABSENT = "ABSENT";

    private final CarlandBookingFeign carlandBookingFeign;

    @Value("${carland.internal-token:}")
    private String internalToken;

    public void assertOpen(StaffAccount account, String acceptLanguage) {
        if (account != null && Boolean.TRUE.equals(account.getManuallyDisabled())) {
            throw suspended(acceptLanguage);
        }
        String result = gate(account == null ? null : account.getId());
        if (SUSPENDED.equals(result)) {
            throw suspended(acceptLanguage);
        }
        if (!ALLOWED.equals(result)) {
            throw new UserNotFoundException(
                    EnumMessagesLangValues.STAFF_USER_NOT_FOUND.getMessageByLang(acceptLanguage));
        }
    }

    private String gate(Long staffId) {
        if (staffId == null) {
            return ABSENT;
        }
        if (!StringUtils.hasText(internalToken)) {
            throw new AuthApiException("INTERNAL_TOKEN_NOT_CONFIGURED",
                    EnumMessagesLangValues.STAFF_GATE_UNAVAILABLE.getMessageByLang("az"),
                    HttpStatus.SERVICE_UNAVAILABLE);
        }
        try {
            StaffLoginGateResponse body = carlandBookingFeign.loginGate(internalToken, staffId);
            if (body == null || body.getResult() == null) {
                return SUSPENDED;
            }
            return body.getResult();
        } catch (AuthApiException ex) {
            throw ex;
        } catch (Exception ex) {
            log.warn("STAFF_GATE_FAIL staffId={}", staffId);
            throw new AuthApiException("STAFF_GATE_UNAVAILABLE",
                    EnumMessagesLangValues.STAFF_GATE_UNAVAILABLE.getMessageByLang("az"),
                    HttpStatus.SERVICE_UNAVAILABLE);
        }
    }

    private static AuthApiException suspended(String acceptLanguage) {
        return new AuthApiException("COOPERATION_SUSPENDED",
                EnumMessagesLangValues.COOPERATION_SUSPENDED.getMessageByLang(acceptLanguage),
                HttpStatus.FORBIDDEN);
    }
}
