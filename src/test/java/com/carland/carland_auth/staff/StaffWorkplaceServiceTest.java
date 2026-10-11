package com.carland.carland_auth.staff;

import com.carland.carland_auth.entity.StaffAccount;
import com.carland.carland_auth.exceptions.AuthApiException;
import com.carland.carland_auth.feign.CarlandBookingFeign;
import com.carland.carland_auth.staff.dto.StaffLoginGateResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StaffWorkplaceServiceTest {

    @Mock CarlandBookingFeign carlandBookingFeign;
    @InjectMocks StaffWorkplaceService service;

    @BeforeEach
    void token() {
        ReflectionTestUtils.setField(service, "internalToken", "x");
    }

    @Test
    void handClosedStaffIsRejectedWithoutAskingPlace() {
        StaffAccount account = StaffAccount.builder().id(StaffIds.MIN_ID).manuallyDisabled(true).build();
        AuthApiException ex = assertThrows(AuthApiException.class, () -> service.assertOpen(account, "az"));
        assertEquals("Əməkdaşlıq dayandırılıb", ex.getMessage());
    }

    @Test
    void closedPlaceIsRejected() {
        StaffAccount account = StaffAccount.builder().id(StaffIds.MIN_ID).manuallyDisabled(false).build();
        when(carlandBookingFeign.loginGate("x", StaffIds.MIN_ID))
                .thenReturn(StaffLoginGateResponse.builder().result("SUSPENDED").build());
        AuthApiException ex = assertThrows(AuthApiException.class, () -> service.assertOpen(account, "en"));
        assertEquals("Cooperation has been suspended", ex.getMessage());
    }

    @Test
    void openPlacePasses() {
        StaffAccount account = StaffAccount.builder().id(StaffIds.MIN_ID).build();
        when(carlandBookingFeign.loginGate("x", StaffIds.MIN_ID))
                .thenReturn(StaffLoginGateResponse.builder().result("ALLOWED").build());
        service.assertOpen(account, "az");
    }
}
