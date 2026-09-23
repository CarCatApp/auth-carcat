package com.carland.carland_auth.staff;

import com.carland.carland_auth.entity.Otp;
import com.carland.carland_auth.entity.User;
import com.carland.carland_auth.enums.OtpStatus;
import com.carland.carland_auth.enums.UserRoles;
import com.carland.carland_auth.enums.UserStatus;
import com.carland.carland_auth.feign.CarlandBookingFeign;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.repository.OtpRepository;
import com.carland.carland_auth.repository.UserRepository;
import com.carland.carland_auth.service.interfaces.RefreshTokenService;
import com.carland.carland_auth.service.interfaces.SMSService;
import com.carland.carland_auth.staff.dto.StaffPasswordForgotRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StaffPasswordResetServiceTest {

    @Mock UserRepository userRepository;
    @Mock OtpRepository otpRepository;
    @Mock SMSService smsService;
    @Mock StaffMailSender staffMailSender;
    @Mock JWTService jwtService;
    @Mock BCryptPasswordEncoder passwordEncoder;
    @Mock RefreshTokenService refreshTokenService;
    @Mock CarlandBookingFeign carlandBookingFeign;

    @InjectMocks StaffPasswordResetService service;

    @BeforeEach
    void exp() {
        ReflectionTestUtils.setField(service, "expirationMinutes", 3L);
        ReflectionTestUtils.setField(service, "resetTokenExpiration", 360L);
        ReflectionTestUtils.setField(service, "accessTokenExpiration", 900L);
        ReflectionTestUtils.setField(service, "internalToken", "x");
    }

    @Test
    void forgotUnknownUserStillOk() {
        when(userRepository.findByPhoneNumber("+994778844221")).thenReturn(null);
        var out = service.forgot(StaffPasswordForgotRequest.builder()
                .phoneNumber("+994778844221")
                .channel("SMS")
                .build(), "az");
        assertNotNull(out.getMessage());
        verify(smsService, never()).sendOtpToPhone(any(), any(), any());
        verify(smsService, never()).sendSms(any(), any());
    }

    @Test
    void forgotSmsSendsOtp() {
        User user = User.builder()
                .id(9L)
                .phoneNumber("+994778844221")
                .role(UserRoles.BRANCH_ADMIN.name())
                .status(UserStatus.ACTIVE.name())
                .build();
        when(userRepository.findByPhoneNumber("+994778844221")).thenReturn(user);
        when(otpRepository.findAllByUserIdAndStatus(9L, OtpStatus.PENDING.name())).thenReturn(List.of());
        when(otpRepository.save(any(Otp.class))).thenAnswer(inv -> inv.getArgument(0));

        service.forgot(StaffPasswordForgotRequest.builder()
                .phoneNumber("0778844221")
                .channel("SMS")
                .build(), "az");

        verify(smsService).sendOtpToPhone(eq("+994709957000"), any(), eq("az"));
        verify(smsService, never()).sendSms(any(), any());
        verify(staffMailSender, never()).sendHtml(any(), any(), any());
    }

    @Test
    void notifySmsSendsAsciiTextAsIs() {
        service.notifySms("+994778844221", "Tek istifadelik sifreniz: 'uuid-here'");
        verify(smsService).sendTextToPhone(eq("+994709957000"),
                eq("Tek istifadelik sifreniz: 'uuid-here'"));
    }
}
