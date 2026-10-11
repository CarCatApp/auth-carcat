package com.carland.carland_auth.staff;

import com.carland.carland_auth.entity.StaffAccount;
import com.carland.carland_auth.entity.StaffOtp;
import com.carland.carland_auth.enums.OtpStatus;
import com.carland.carland_auth.feign.CarlandBookingFeign;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.repository.StaffAccountRepository;
import com.carland.carland_auth.repository.StaffOtpRepository;
import com.carland.carland_auth.service.interfaces.SMSService;
import com.carland.carland_auth.staff.dto.StaffPasswordForgotRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StaffPasswordResetServiceTest {

    @Mock StaffAccountRepository staffAccountRepository;
    @Mock StaffOtpRepository staffOtpRepository;
    @Mock StaffOtpHasher staffOtpHasher;
    @Mock SMSService smsService;
    @Mock StaffMailSender staffMailSender;
    @Mock JWTService jwtService;
    @Mock BCryptPasswordEncoder passwordEncoder;
    @Mock CarlandBookingFeign carlandBookingFeign;
    @Mock StaffWorkplaceService staffWorkplaceService;

    @InjectMocks StaffPasswordResetService service;

    @BeforeEach
    void exp() {
        ReflectionTestUtils.setField(service, "expirationMinutes", 3L);
        ReflectionTestUtils.setField(service, "resetTokenExpiration", 360L);
        ReflectionTestUtils.setField(service, "staffAccessTokenSeconds", 18000L);
        ReflectionTestUtils.setField(service, "maxVerifyAttempts", 3);
        ReflectionTestUtils.setField(service, "internalToken", "x");
    }

    @Test
    void forgotUnknownUserStillOk() {
        when(staffAccountRepository.findByPhoneNumber("+994778844221")).thenReturn(null);
        var out = service.forgot(StaffPasswordForgotRequest.builder()
                .phoneNumber("+994778844221")
                .channel("SMS")
                .build(), "az");
        assertNotNull(out.getMessage());
        verify(smsService, never()).sendOtpToPhone(any(), any(), any());
        verify(smsService, never()).sendSms(any(), any());
    }

    @Test
    void forgotSmsStoresHashNotPlaintext() {
        StaffAccount account = StaffAccount.builder()
                .id(StaffIds.MIN_ID)
                .phoneNumber("+994778844221")
                .role("BRANCH_ADMIN")
                .status(StaffAccountStatus.ACTIVE.name())
                .build();
        when(staffAccountRepository.findByPhoneNumber("+994778844221")).thenReturn(account);
        when(staffOtpRepository.findAllByStaffAccountIdAndStatus(StaffIds.MIN_ID, OtpStatus.PENDING.name()))
                .thenReturn(List.of());
        when(staffOtpHasher.hash(anyString())).thenReturn("hmac");
        when(staffOtpRepository.save(any(StaffOtp.class))).thenAnswer(inv -> inv.getArgument(0));

        service.forgot(StaffPasswordForgotRequest.builder()
                .phoneNumber("+994778844221")
                .channel("SMS")
                .build(), "az");

        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);
        verify(staffOtpHasher).hash(code.capture());
        ArgumentCaptor<StaffOtp> saved = ArgumentCaptor.forClass(StaffOtp.class);
        verify(staffOtpRepository).save(saved.capture());
        assertEquals("hmac", saved.getValue().getCodeHash());
        assertNotEquals(code.getValue(), saved.getValue().getCodeHash());
        verify(smsService).sendOtpToPhone(eq("+994778844221"), eq(code.getValue()), eq("az"));
        verify(smsService, never()).sendSms(any(), any());
        verify(staffMailSender, never()).sendHtml(any(), any(), any());
    }

    @Test
    void notifySmsSendsAsciiTextAsIs() {
        service.notifySms("+994778844221", "Tek istifadelik sifreniz: 'uuid-here'");
        verify(smsService).sendTextToPhone(eq("+994778844221"),
                eq("Tek istifadelik sifreniz: 'uuid-here'"));
    }
}
