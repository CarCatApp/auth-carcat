package com.carland.carland_auth.dto.response;

import lombok.*;
import lombok.experimental.FieldDefaults;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserResponse {
    String accessToken;
    String  refreshToken;
    String role;
    String message;
    String name;
    String surname;
    Long userId;
    String phoneNumber;
    Boolean mustChangePassword;
}
