package com.carland.carland_auth.staff.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StaffPasswordVerifyRequest {
    String phoneNumber;
    String email;
    String otp;
}
