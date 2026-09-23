package com.carland.carland_auth.service.impl;

import com.carland.carland_auth.feign.LsimFeign;
import com.carland.carland_auth.repository.OtpRepository;
import com.carland.carland_auth.repository.UserRepository;
import com.carland.carland_auth.service.SmsBalanceAlertService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class SMSServiceImplTest {

    @Mock UserRepository userRepository;
    @Mock OtpRepository otpRepository;
    @Mock LsimFeign lsimFeign;
    @Mock SmsBalanceAlertService smsBalanceAlertService;

    @InjectMocks SMSServiceImpl smsService;

    @BeforeEach
    void lsim() {
        ReflectionTestUtils.setField(smsService, "login", "login");
        ReflectionTestUtils.setField(smsService, "password", "pass");
        ReflectionTestUtils.setField(smsService, "sender", "CarCat");
        ReflectionTestUtils.setField(smsService, "expirationMinutes", 3L);
        org.mockito.Mockito.lenient()
                .when(lsimFeign.sendSms(anyString(), anyString(), anyString(), anyString(), anyString(), anyBoolean()))
                .thenReturn("{\"obj\":1}");
    }

    @Test
    void asciiInviteUsesGsmNotUnicode() {
        String text = "Tek istifadelik sifreniz: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'";
        smsService.sendTextToPhone("+994709957000", text);
        ArgumentCaptor<Boolean> unicode = ArgumentCaptor.forClass(Boolean.class);
        verify(lsimFeign).sendSms(eq("login"), eq("994709957000"), eq(text), eq("CarCat"),
                anyString(), unicode.capture());
        assertFalse(unicode.getValue());
        assertFalse(SMSServiceImpl.needsUnicode(text));
    }

    @Test
    void otpSendIsSameDispatchAscii() {
        smsService.sendOtpToPhone("+994709957000", "123456", "az");
        verify(lsimFeign).sendSms(eq("login"), eq("994709957000"),
                eq("CarCat otp kodunuz: 123456"), eq("CarCat"), anyString(), eq(false));
    }

    @Test
    void unicodeCharsNeedFlag() {
        assertTrue(SMSServiceImpl.needsUnicode("sifreniz".replace("s", "\u015F")));
        assertTrue(SMSServiceImpl.needsUnicode("CarCat staff \u015Fifr\u0259niz"));
        assertFalse(SMSServiceImpl.needsUnicode("Tek istifadelik sifreniz"));
    }
}
