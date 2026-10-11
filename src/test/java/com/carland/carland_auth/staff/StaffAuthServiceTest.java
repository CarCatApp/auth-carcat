package com.carland.carland_auth.staff;

import com.carland.carland_auth.entity.StaffAccount;
import com.carland.carland_auth.exceptions.AuthApiException;
import com.carland.carland_auth.exceptions.PinLockedException;
import com.carland.carland_auth.exceptions.UserNotFoundException;
import com.carland.carland_auth.exceptions.UsernameAlreadyExistException;
import com.carland.carland_auth.exceptions.WrongPasswordException;
import com.carland.carland_auth.feign.CarlandBookingFeign;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.repository.StaffAccountRepository;
import com.carland.carland_auth.staff.dto.StaffProvisionRequest;
import com.carland.carland_auth.dto.request.UserRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StaffAuthServiceTest {

    @Mock StaffAccountRepository staffAccountRepository;
    @Mock BCryptPasswordEncoder passwordEncoder;
    @Mock JWTService jwtService;
    @Mock CarlandBookingFeign carlandBookingFeign;
    @Mock StaffLoginAttemptService staffLoginAttemptService;

    @InjectMocks StaffAuthService service;

    @BeforeEach
    void exp() {
        ReflectionTestUtils.setField(service, "staffAccessTokenSeconds", 18000L);
        ReflectionTestUtils.setField(service, "internalToken", "x");
    }

    @Test
    void provisionRejectsExistingPhone() {
        when(staffAccountRepository.existsByPhoneNumber("+994709957000")).thenReturn(true);
        StaffProvisionRequest req = StaffProvisionRequest.builder()
                .phoneNumber("0709957000")
                .role("PARTNER_ADMIN")
                .build();
        assertThrows(UsernameAlreadyExistException.class, () -> service.provision(req, "az"));
        verify(staffAccountRepository, never()).save(any());
    }

    @Test
    void provisionCreatesInvitedStaff() {
        when(staffAccountRepository.existsByPhoneNumber("+994709957000")).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("hash");
        when(staffAccountRepository.save(any(StaffAccount.class))).thenAnswer(inv -> {
            StaffAccount account = inv.getArgument(0);
            account.setId(StaffIds.MIN_ID);
            return account;
        });
        var out = service.provision(StaffProvisionRequest.builder()
                .phoneNumber("+994709957000")
                .role("BRANCH_ADMIN")
                .build(), "az");
        assertEquals(StaffIds.MIN_ID, out.getUserId());
        assertNotNull(out.getOneTimePassword());
        ArgumentCaptor<StaffAccount> cap = ArgumentCaptor.forClass(StaffAccount.class);
        verify(staffAccountRepository).save(cap.capture());
        assertEquals(StaffAccountStatus.INVITED.name(), cap.getValue().getStatus());
        assertEquals("BRANCH_ADMIN", cap.getValue().getRole());
        assertEquals("hash", cap.getValue().getStaffPassword());
    }

    @Test
    void provisionRejectsIdInCustomerRange() {
        when(staffAccountRepository.existsByPhoneNumber("+994709957000")).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("hash");
        when(staffAccountRepository.save(any(StaffAccount.class))).thenAnswer(inv -> {
            StaffAccount account = inv.getArgument(0);
            account.setId(42L);
            return account;
        });
        assertThrows(AuthApiException.class, () -> service.provision(StaffProvisionRequest.builder()
                .phoneNumber("+994709957000")
                .role("BRANCH_ADMIN")
                .build(), "az"));
        verify(staffAccountRepository).delete(any(StaffAccount.class));
    }

    @Test
    void loginRejectsWhenAccountLocked() {
        StaffAccount account = openAccount();
        account.setLockedUntil(LocalDateTime.now().plusMinutes(5));
        when(staffAccountRepository.findByPhoneNumber("+994709957000")).thenReturn(account);
        when(staffAccountRepository.findById(StaffIds.MIN_ID)).thenReturn(Optional.of(account));
        UserRequest req = UserRequest.builder()
                .phoneNumber("+994709957000")
                .password("secret12")
                .build();
        assertThrows(PinLockedException.class, () -> service.login(req, "az"));
    }

    @Test
    void loginLocksAfterFailedAttempts() {
        StaffAccount account = openAccount();
        when(staffAccountRepository.findByPhoneNumber("+994709957000")).thenReturn(account);
        when(staffAccountRepository.findById(StaffIds.MIN_ID)).thenReturn(Optional.of(account));
        when(passwordEncoder.matches("wrongpass", "hash")).thenReturn(false);
        when(staffLoginAttemptService.recordWrongPassword(StaffIds.MIN_ID))
                .thenReturn(new StaffLoginAttemptService.Result(true, LocalDateTime.now().plusMinutes(5), 300));
        UserRequest req = UserRequest.builder()
                .phoneNumber("+994709957000")
                .password("wrongpass")
                .build();
        assertThrows(PinLockedException.class, () -> service.login(req, "az"));
    }

    @Test
    void loginByEmailUsesFiveHourToken() {
        StaffAccount account = openAccount();
        when(staffAccountRepository.findByEmailIgnoreCase("staff@example.com")).thenReturn(account);
        when(staffAccountRepository.findById(StaffIds.MIN_ID)).thenReturn(Optional.of(account));
        when(passwordEncoder.matches("secret12", "hash")).thenReturn(true);
        when(jwtService.generateStaffAccessToken(
                eq(StaffIds.MIN_ID), eq("+994709957000"), eq("BRANCH_ADMIN"),
                isNull(), isNull(), eq(18000L), eq(false))).thenReturn("tok");
        UserRequest req = UserRequest.builder()
                .email("staff@example.com")
                .password("secret12")
                .build();
        var out = service.login(req, "az");
        assertEquals("tok", out.getAccessToken());
        assertEquals("+994709957000", out.getPhoneNumber());
        assertEquals(Boolean.FALSE, out.getMustChangePassword());
    }

    @Test
    void loginWrongPasswordWithoutLock() {
        StaffAccount account = openAccount();
        when(staffAccountRepository.findByPhoneNumber("+994709957000")).thenReturn(account);
        when(staffAccountRepository.findById(StaffIds.MIN_ID)).thenReturn(Optional.of(account));
        when(passwordEncoder.matches("wrongpass", "hash")).thenReturn(false);
        when(staffLoginAttemptService.recordWrongPassword(StaffIds.MIN_ID))
                .thenReturn(new StaffLoginAttemptService.Result(false, null, 0));
        UserRequest req = UserRequest.builder()
                .phoneNumber("+994709957000")
                .password("wrongpass")
                .build();
        WrongPasswordException ex = assertThrows(WrongPasswordException.class, () -> service.login(req, "az"));
        assertEquals("İstifadəçi məlumatı və ya şifrə yanlışdır", ex.getMessage());
    }

    @Test
    void loginUnknownPhoneSaysUserNotFound() {
        when(staffAccountRepository.findByPhoneNumber("+994500000001")).thenReturn(null);
        UserRequest req = UserRequest.builder()
                .phoneNumber("+994500000001")
                .password("20262026")
                .build();
        UserNotFoundException ex = assertThrows(UserNotFoundException.class, () -> service.login(req, "az"));
        assertEquals("İstifadəçi tapılmadı", ex.getMessage());
    }

    @Test
    void loginUnknownEmailSaysUserNotFound() {
        when(staffAccountRepository.findByEmailIgnoreCase("ghost@example.com")).thenReturn(null);
        UserRequest req = UserRequest.builder()
                .email("ghost@example.com")
                .password("20262026")
                .build();
        UserNotFoundException ex = assertThrows(UserNotFoundException.class, () -> service.login(req, "az"));
        assertEquals("İstifadəçi tapılmadı", ex.getMessage());
    }

    @Test
    void customerPhoneIsNotAStaffLogin() {
        when(staffAccountRepository.findByPhoneNumber("+994709957000")).thenReturn(null);
        UserRequest req = UserRequest.builder()
                .phoneNumber("+994709957000")
                .password("20262026")
                .build();
        UserNotFoundException ex = assertThrows(UserNotFoundException.class, () -> service.login(req, "az"));
        assertEquals("İstifadəçi tapılmadı", ex.getMessage());
    }

    @Test
    void loginRejectsPhoneWithoutPlus994() {
        UserRequest req = UserRequest.builder()
                .phoneNumber("0709957840")
                .password("20262026")
                .build();
        AuthApiException ex = assertThrows(AuthApiException.class, () -> service.login(req, "az"));
        assertEquals("INVALID_PHONE", ex.getError());
        assertEquals("Telefon nömrəsi +994 ilə başlamalıdır", ex.getMessage());
    }

    @Test
    void loginRejectsUnknownOperator() {
        UserRequest req = UserRequest.builder()
                .phoneNumber("+994129957000")
                .password("20262026")
                .build();
        AuthApiException ex = assertThrows(AuthApiException.class, () -> service.login(req, "az"));
        assertEquals("UNKNOWN_OPERATOR", ex.getError());
        assertEquals("Naməlum mobil operator", ex.getMessage());
    }

    @Test
    void loginRejectsShortPassword() {
        UserRequest req = UserRequest.builder()
                .phoneNumber("+994709957000")
                .password("1234567")
                .build();
        AuthApiException ex = assertThrows(AuthApiException.class, () -> service.login(req, "az"));
        assertEquals("WEAK_PASSWORD", ex.getError());
        assertEquals("Zəif şifrə. Minimum 8 simvol istifadə edin", ex.getMessage());
    }

    private static StaffAccount openAccount() {
        return StaffAccount.builder()
                .id(StaffIds.MIN_ID)
                .phoneNumber("+994709957000")
                .email("staff@example.com")
                .role("BRANCH_ADMIN")
                .status(StaffAccountStatus.ACTIVE.name())
                .staffPassword("hash")
                .build();
    }
}
