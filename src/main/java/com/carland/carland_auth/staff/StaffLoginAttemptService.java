package com.carland.carland_auth.staff;

import com.carland.carland_auth.entity.User;
import com.carland.carland_auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Staff password lockout counters. Same User columns as PIN lockout; staff accounts do not use PIN.
 * Thresholds come from staff.login.* properties, not hardcoded.
 */
@Service
@RequiredArgsConstructor
public class StaffLoginAttemptService {

    @Value("${staff.login.max-attempts:3}")
    private int maxAttempts;

    @Value("${staff.login.attempt-window-minutes:10}")
    private int attemptWindowMinutes;

    @Value("${staff.login.lock-duration-minutes:5}")
    private int lockDurationMinutes;

    private final UserRepository userRepository;

    public record Result(boolean locked, LocalDateTime lockedUntil, long remainingSeconds) {
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Result recordWrongPassword(Long userId) {
        User user = userRepository.findById(userId).orElseThrow();
        LocalDateTime now = LocalDateTime.now();

        if (user.getPinLockedUntil() != null && user.getPinLockedUntil().isAfter(now)) {
            long remaining = Math.max(1, java.time.Duration.between(now, user.getPinLockedUntil()).getSeconds());
            return new Result(true, user.getPinLockedUntil(), remaining);
        }

        int attempts;
        if (user.getLastFailedPinAt() == null
                || user.getLastFailedPinAt().isBefore(now.minusMinutes(attemptWindowMinutes))) {
            attempts = 1;
        } else {
            int current = user.getFailedPinAttempts() == null ? 0 : user.getFailedPinAttempts();
            attempts = current + 1;
        }

        user.setFailedPinAttempts(attempts);
        user.setLastFailedPinAt(now);

        if (attempts >= maxAttempts) {
            LocalDateTime until = now.plusMinutes(lockDurationMinutes);
            user.setPinLockedUntil(until);
            user.setFailedPinAttempts(0);
            userRepository.save(user);
            long remaining = Math.max(1, java.time.Duration.between(now, until).getSeconds());
            return new Result(true, until, remaining);
        }

        userRepository.save(user);
        return new Result(false, null, 0);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void clearFailureState(Long userId) {
        User user = userRepository.findById(userId).orElseThrow();
        user.setFailedPinAttempts(0);
        user.setLastFailedPinAt(null);
        user.setPinLockedUntil(null);
        userRepository.save(user);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void clearExpiredLock(Long userId) {
        User user = userRepository.findById(userId).orElseThrow();
        if (user.getPinLockedUntil() != null && !user.getPinLockedUntil().isAfter(LocalDateTime.now())) {
            user.setPinLockedUntil(null);
            userRepository.save(user);
        }
    }
}
