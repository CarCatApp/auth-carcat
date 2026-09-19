package com.carland.carland_auth.staff;

import com.carland.carland_auth.entity.User;
import com.carland.carland_auth.repository.UserRepository;
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

    @Mock UserRepository userRepository;
    @InjectMocks StaffLoginAttemptService service;

    @BeforeEach
    void props() {
        ReflectionTestUtils.setField(service, "maxAttempts", 3);
        ReflectionTestUtils.setField(service, "attemptWindowMinutes", 10);
        ReflectionTestUtils.setField(service, "lockDurationMinutes", 5);
    }

    @Test
    void thirdFailureLocks() {
        User user = User.builder()
                .id(1L)
                .failedPinAttempts(2)
                .lastFailedPinAt(LocalDateTime.now())
                .build();
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        StaffLoginAttemptService.Result result = service.recordWrongPassword(1L);
        assertTrue(result.locked());
        assertTrue(user.getPinLockedUntil().isAfter(LocalDateTime.now().minusSeconds(1)));
    }

    @Test
    void firstFailureDoesNotLock() {
        User user = User.builder().id(1L).failedPinAttempts(0).build();
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        StaffLoginAttemptService.Result result = service.recordWrongPassword(1L);
        assertFalse(result.locked());
    }
}
