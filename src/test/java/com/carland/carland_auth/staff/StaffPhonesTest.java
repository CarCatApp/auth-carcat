package com.carland.carland_auth.staff;

import com.carland.carland_auth.exceptions.AuthApiException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StaffPhonesTest {

    @Test
    void acceptsSpacedPlus994() {
        assertEquals("+994709957000", StaffPhones.requireLoginPhone("+994 70 995 70 00", "az"));
    }

    @Test
    void blankIsNull() {
        assertNull(StaffPhones.requireLoginPhone("  ", "az"));
    }

    @Test
    void rejectsMissingPlus994() {
        AuthApiException ex = assertThrows(AuthApiException.class,
                () -> StaffPhones.requireLoginPhone("0709957000", "az"));
        assertEquals("INVALID_PHONE", ex.getError());
        assertEquals("Telefon nömrəsi +994 ilə başlamalıdır", ex.getMessage());
    }

    @Test
    void rejectsForeignPrefix() {
        AuthApiException ex = assertThrows(AuthApiException.class,
                () -> StaffPhones.requireLoginPhone("+905551112233", "az"));
        assertEquals("INVALID_PHONE", ex.getError());
        assertEquals("Telefon nömrəsi +994 ilə başlamalıdır", ex.getMessage());
    }

    @Test
    void rejectsUnknownOperator() {
        AuthApiException ex = assertThrows(AuthApiException.class,
                () -> StaffPhones.requireLoginPhone("+994129957000", "az"));
        assertEquals("UNKNOWN_OPERATOR", ex.getError());
        assertEquals("Naməlum mobil operator", ex.getMessage());
    }

    @Test
    void rejectsShortAfterValidOperator() {
        AuthApiException ex = assertThrows(AuthApiException.class,
                () -> StaffPhones.requireLoginPhone("+99470995", "az"));
        assertEquals("INVALID_PHONE", ex.getError());
        assertEquals("Telefon nömrəsi düzgün deyil", ex.getMessage());
    }
}
