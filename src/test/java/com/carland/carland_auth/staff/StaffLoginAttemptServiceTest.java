package com.carland.carland_auth.staff;

import com.carland.carland_auth.entity.StaffAccount;
import com.carland.carland_auth.repository.StaffAccountRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StaffLoginAttemptServiceTest {

    @Mock StaffAccountRepository staffAccountRepository;
    @InjectMocks StaffLoginAttemptService service;

    @BeforeEach
    void props() {
        ReflectionTestUtils.setField(service, "maxAttempts", 3);
        ReflectionTestUtils.setField(service, "attemptWindowMinutes", 10);
        ReflectionTestUtils.setField(service, "lockDurationMinutes", 5);
    }

    @Test
    void thirdFailureLocks() {
        StaffAccount account = StaffAccount.builder()
                .id(StaffIds.MIN_ID)
                .failedAttempts(2)
                .lastFailedAt(LocalDateTime.now())
                .build();
        when(staffAccountRepository.findById(StaffIds.MIN_ID)).thenReturn(Optional.of(account));
        when(staffAccountRepository.save(any(StaffAccount.class))).thenAnswer(inv -> inv.getArgument(0));

        StaffLoginAttemptService.Result result = service.recordWrongPassword(StaffIds.MIN_ID);
        assertTrue(result.locked());
        assertTrue(account.getLockedUntil().isAfter(LocalDateTime.now().minusSeconds(1)));
    }

    @Test
    void firstFailureDoesNotLock() {
        StaffAccount account = StaffAccount.builder().id(StaffIds.MIN_ID).failedAttempts(0).build();
        when(staffAccountRepository.findById(StaffIds.MIN_ID)).thenReturn(Optional.of(account));
        when(staffAccountRepository.save(any(StaffAccount.class))).thenAnswer(inv -> inv.getArgument(0));

        StaffLoginAttemptService.Result result = service.recordWrongPassword(StaffIds.MIN_ID);
        assertFalse(result.locked());
    }
}
