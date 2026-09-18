package com.carland.carland_auth.staff;

import com.carland.carland_auth.enums.UserRoles;
import com.carland.carland_auth.enums.UserStatus;
import com.carland.carland_auth.exceptions.UsernameAlreadyExistException;
import com.carland.carland_auth.feign.CarlandBookingFeign;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.repository.UserRepository;
import com.carland.carland_auth.service.interfaces.RefreshTokenService;
import com.carland.carland_auth.staff.dto.StaffProvisionRequest;
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
}
