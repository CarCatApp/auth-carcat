package com.carland.carland_auth.dto.request;

import com.fasterxml.jackson.annotation.JsonAlias;
import lombok.*;
import lombok.experimental.FieldDefaults;


@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
@FieldDefaults(level = AccessLevel.PRIVATE)

public class UserRequest {

    String phoneNumber;

    String email;

    @JsonAlias({"pin", "pinCode"})
    String password;

    String pin;

    String pinCode;

    String name;
    String surname;

    /** PO login field (NewUsers). Alias deviceToken for FCM-style clients. */
    @JsonAlias({"deviceToken"})
    String deviceId;

    String platform;

    String purpose;

    @JsonAlias({"authenticationToken", "registerToken"})
    String authToken;

    /** NewUsers setPinCode — token from /otp/verify response. */
    String pinSetupToken;

    public String resolveCredential() {
        if (pinCode != null && !pinCode.isBlank()) {
            return pinCode;
        }
        if (password != null && !password.isBlank()) {
            return password;
        }
        if (pin != null && !pin.isBlank()) {
            return pin;
        }
        return null;
    }
}
