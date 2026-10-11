package com.carland.carland_auth.staff;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StaffOtpHasherTest {

    @Test
    void hashIsNotTheCodeAndMatches() {
        StaffOtpHasher hasher = new StaffOtpHasher();
        ReflectionTestUtils.setField(hasher, "pepper", "test-pepper");
        String hash = hasher.hash("123456");
        assertNotEquals("123456", hash);
        assertTrue(hasher.matches("123456", hash));
        assertFalse(hasher.matches("123457", hash));
    }
}
