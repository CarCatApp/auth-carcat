package com.carland.carland_auth.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class PhoneNumbersTest {

    @Test
    void plus994PassThrough() {
        assertEquals("+994709957000", PhoneNumbers.normalize("+994709957000"));
    }

    @Test
    void leadingZeroBecomesPlus994() {
        assertEquals("+994709957000", PhoneNumbers.normalize("070 995 70 00"));
    }

    @Test
    void rejectsBad() {
        assertNull(PhoneNumbers.normalize("abc"));
    }
}
