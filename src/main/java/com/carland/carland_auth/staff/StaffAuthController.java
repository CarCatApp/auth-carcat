package com.carland.carland_auth.staff;

import com.carland.carland_auth.dto.request.UserRequest;
import com.carland.carland_auth.dto.response.UserResponse;
import com.carland.carland_auth.exceptions.AuthApiException;
import com.carland.carland_auth.security.InternalTokenValidator;
import com.carland.carland_auth.staff.dto.StaffDisableRequest;
import com.carland.carland_auth.staff.dto.StaffPasswordChangeRequest;
import com.carland.carland_auth.staff.dto.StaffProvisionRequest;
import com.carland.carland_auth.staff.dto.StaffProvisionResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class StaffAuthController {

    private final StaffAuthService staffAuthService;
    private final InternalTokenValidator internalTokenValidator;

    @PostMapping("/api/v1/internal/staff/provision")
    public StaffProvisionResponse provision(@RequestBody StaffProvisionRequest request,
                                            HttpServletRequest httpRequest,
                                            @RequestHeader(value = "Accept-Language", required = false) String acceptLanguage) {
        assertInternalToken(httpRequest);
        return staffAuthService.provision(request, lang(acceptLanguage));
    }

    @PostMapping("/api/v1/internal/staff/disable")
    public void disable(@RequestBody StaffDisableRequest request,
                        HttpServletRequest httpRequest) {
        assertInternalToken(httpRequest);
        staffAuthService.disable(request);
    }

    @PostMapping("/api/v1/staff/login")
    public UserResponse login(@RequestBody UserRequest request,
                              @RequestHeader(value = "Accept-Language", required = false) String acceptLanguage) {
        return staffAuthService.login(request, lang(acceptLanguage));
    }

    @PutMapping("/api/v1/staff/me/own-password")
    public UserResponse setOwnPassword(@RequestBody StaffPasswordChangeRequest request,
                                       @RequestHeader(value = "Accept-Language", required = false) String acceptLanguage) {
        return staffAuthService.changePassword(request, lang(acceptLanguage));
    }

    private void assertInternalToken(HttpServletRequest request) {
        if (!internalTokenValidator.isConfigured()) {
            throw new AuthApiException("INTERNAL_TOKEN_NOT_CONFIGURED",
                    "CARLAND_INTERNAL_TOKEN is not set", HttpStatus.SERVICE_UNAVAILABLE);
        }
        if (!internalTokenValidator.matches(request)) {
            throw new AuthApiException("INVALID_INTERNAL_TOKEN",
                    "X-Internal-Token is missing or invalid", HttpStatus.UNAUTHORIZED);
        }
    }

    private static String lang(String acceptLanguage) {
        return acceptLanguage == null || acceptLanguage.isBlank() ? "az" : acceptLanguage;
    }
}
