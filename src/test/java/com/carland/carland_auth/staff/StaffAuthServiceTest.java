package com.carland.carland_auth.staff;

import com.carland.carland_auth.enums.UserRoles;
import com.carland.carland_auth.enums.UserStatus;
import com.carland.carland_auth.exceptions.AuthApiException;
import com.carland.carland_auth.exceptions.PinLockedException;
import com.carland.carland_auth.exceptions.UserNotFoundException;
import com.carland.carland_auth.exceptions.UsernameAlreadyExistException;
import com.carland.carland_auth.exceptions.WrongPasswordException;
import com.carland.carland_auth.feign.CarlandBookingFeign;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.repository.UserRepository;
import com.carland.carland_auth.service.interfaces.RefreshTokenService;
import com.carland.carland_auth.staff.dto.StaffProvisionRequest;
import com.carland.carland_auth.dto.request.UserRequest;
import com.carland.carland_auth.entity.User;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StaffAuthServiceTest {

    @Mock UserRepository userRepository;
    @Mock BCryptPasswordEncoder passwordEncoder;
    @Mock JWTService jwtService;
    @Mock RefreshTokenService refreshTokenService;
    @Mock CarlandBookingFeign carlandBookingFeign;
    @Mock StaffLoginAttemptService staffLoginAttemptService;

    @InjectMocks StaffAuthService service;

    @BeforeEach
    void exp() {
        ReflectionTestUtils.setField(service, "accessTokenExpiration", 900L);
        ReflectionTestUtils.setField(service, "internalToken", "x");
    }

    @Test
    void provisionRejectsExistingPhone() {
        when(userRepository.findByPhoneNumber("+994709957000")).thenReturn(User.builder().id(1L).build());
        StaffProvisionRequest req = StaffProvisionRequest.builder()
                .phoneNumber("0709957000")
                .role("PARTNER_ADMIN")
                .build();
        assertThrows(UsernameAlreadyExistException.class, () -> service.provision(req, "az"));
    }

    @Test
    void provisionCreatesInvitedStaff() {
        when(userRepository.findByPhoneNumber("+994709957000")).thenReturn(null);
        when(passwordEncoder.encode(any())).thenReturn("hash");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(42L);
            return u;
        });
        var out = service.provision(StaffProvisionRequest.builder()
                .phoneNumber("+994709957000")
                .role("BRANCH_ADMIN")
                .build(), "az");
        assertEquals(42L, out.getUserId());
        assertNotNull(out.getOneTimePassword());
        ArgumentCaptor<User> cap = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(cap.capture());
        assertEquals(UserStatus.INVITED.name(), cap.getValue().getStatus());
        assertEquals(UserRoles.BRANCH_ADMIN.name(), cap.getValue().getRole());
    }

    @Test
    void loginRejectsWhenAccountLocked() {
        User user = User.builder()
                .id(7L)
                .phoneNumber("+994709957000")
                .role(UserRoles.BRANCH_ADMIN.name())
                .status(UserStatus.ACTIVE.name())
                .pin("hash")
                .pinLockedUntil(LocalDateTime.now().plusMinutes(5))
                .build();
        when(userRepository.findByPhoneNumber("+994709957000")).thenReturn(user);
        when(userRepository.findById(7L)).thenReturn(Optional.of(user));
        UserRequest req = UserRequest.builder()
                .phoneNumber("+994709957000")
                .password("secret12")
                .build();
        assertThrows(PinLockedException.class, () -> service.login(req, "az"));
    }

    @Test
    void loginLocksAfterFailedAttempts() {
        User user = User.builder()
                .id(7L)
                .phoneNumber("+994709957000")
                .role(UserRoles.BRANCH_ADMIN.name())
                .status(UserStatus.ACTIVE.name())
                .pin("hash")
                .build();
        when(userRepository.findByPhoneNumber("+994709957000")).thenReturn(user);
        when(userRepository.findById(7L)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongpass", "hash")).thenReturn(false);
        when(staffLoginAttemptService.recordWrongPassword(7L))
                .thenReturn(new StaffLoginAttemptService.Result(true, LocalDateTime.now().plusMinutes(5), 300));
        UserRequest req = UserRequest.builder()
                .phoneNumber("+994709957000")
                .password("wrongpass")
                .build();
        assertThrows(PinLockedException.class, () -> service.login(req, "az"));
    }

    @Test
    void loginByEmail() {
        User user = User.builder()
                .id(7L)
                .phoneNumber("+994709957000")
                .email("staff@example.com")
                .role(UserRoles.BRANCH_ADMIN.name())
                .status(UserStatus.ACTIVE.name())
                .pin("hash")
                .refreshTokens(new java.util.ArrayList<>())
                .build();
        when(userRepository.findByEmailIgnoreCase("staff@example.com")).thenReturn(user);
        when(userRepository.findById(7L)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret12", "hash")).thenReturn(true);
        when(jwtService.generateAccessToken(user, 900L, false)).thenReturn("tok");
        when(refreshTokenService.createRefreshToken(user)).thenReturn(
                com.carland.carland_auth.entity.RefreshToken.builder().token("r").build());
        when(userRepository.save(user)).thenReturn(user);
        UserRequest req = UserRequest.builder()
                .email("staff@example.com")
                .password("secret12")
                .build();
        var out = service.login(req, "az");
        assertEquals("tok", out.getAccessToken());
        assertEquals("+994709957000", out.getPhoneNumber());
    }

    @Test
    void loginWrongPasswordWithoutLock() {
        User user = User.builder()
                .id(7L)
                .phoneNumber("+994709957000")
                .role(UserRoles.BRANCH_ADMIN.name())
                .status(UserStatus.ACTIVE.name())
                .pin("hash")
                .build();
        when(userRepository.findByPhoneNumber("+994709957000")).thenReturn(user);
        when(userRepository.findById(7L)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongpass", "hash")).thenReturn(false);
        when(staffLoginAttemptService.recordWrongPassword(7L))
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
        when(userRepository.findByPhoneNumber("+994500000001")).thenReturn(null);
        UserRequest req = UserRequest.builder()
                .phoneNumber("+994500000001")
                .password("20262026")
                .build();
        UserNotFoundException ex = assertThrows(UserNotFoundException.class, () -> service.login(req, "az"));
        assertEquals("İstifadəçi tapılmadı", ex.getMessage());
    }

    @Test
    void loginUnknownEmailSaysUserNotFound() {
        when(userRepository.findByEmailIgnoreCase("ghost@example.com")).thenReturn(null);
        UserRequest req = UserRequest.builder()
                .email("ghost@example.com")
                .password("20262026")
                .build();
        UserNotFoundException ex = assertThrows(UserNotFoundException.class, () -> service.login(req, "az"));
        assertEquals("İstifadəçi tapılmadı", ex.getMessage());
    }

    @Test
    void loginOwnerPhoneIsUserNotFoundNotPin() {
        User owner = User.builder()
                .id(9L)
                .phoneNumber("+994709957000")
                .role(UserRoles.USER.name())
                .status(UserStatus.ACTIVE.name())
                .pin("hash")
                .build();
        when(userRepository.findByPhoneNumber("+994709957000")).thenReturn(owner);
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
}
