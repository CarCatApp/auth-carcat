package com.carland.carland_auth.staff.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StaffPasswordForgotRequest {
    String phoneNumber;
    String email;
    String channel;
}
