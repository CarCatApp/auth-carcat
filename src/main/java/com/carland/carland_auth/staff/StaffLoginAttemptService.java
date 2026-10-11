package com.carland.carland_auth.staff;

import com.carland.carland_auth.entity.StaffAccount;
import com.carland.carland_auth.repository.StaffAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Staff password lockout. Counters live on {@code staff_accounts}, not on customer PIN columns.
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

    private final StaffAccountRepository staffAccountRepository;

    public record Result(boolean locked, LocalDateTime lockedUntil, long remainingSeconds) {
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Result recordWrongPassword(Long staffId) {
        StaffAccount account = staffAccountRepository.findById(staffId).orElseThrow();
        LocalDateTime now = LocalDateTime.now();

        if (account.getLockedUntil() != null && account.getLockedUntil().isAfter(now)) {
            long remaining = Math.max(1, java.time.Duration.between(now, account.getLockedUntil()).getSeconds());
            return new Result(true, account.getLockedUntil(), remaining);
        }

        int attempts;
        if (account.getLastFailedAt() == null
                || account.getLastFailedAt().isBefore(now.minusMinutes(attemptWindowMinutes))) {
            attempts = 1;
        } else {
            int current = account.getFailedAttempts() == null ? 0 : account.getFailedAttempts();
            attempts = current + 1;
        }

        account.setFailedAttempts(attempts);
        account.setLastFailedAt(now);

        if (attempts >= maxAttempts) {
            LocalDateTime until = now.plusMinutes(lockDurationMinutes);
            account.setLockedUntil(until);
            account.setFailedAttempts(0);
            staffAccountRepository.save(account);
            long remaining = Math.max(1, java.time.Duration.between(now, until).getSeconds());
            return new Result(true, until, remaining);
        }

        staffAccountRepository.save(account);
        return new Result(false, null, 0);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void clearFailureState(Long staffId) {
        StaffAccount account = staffAccountRepository.findById(staffId).orElseThrow();
        account.setFailedAttempts(0);
        account.setLastFailedAt(null);
        account.setLockedUntil(null);
        staffAccountRepository.save(account);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void clearExpiredLock(Long staffId) {
        StaffAccount account = staffAccountRepository.findById(staffId).orElseThrow();
        if (account.getLockedUntil() != null && !account.getLockedUntil().isAfter(LocalDateTime.now())) {
            account.setLockedUntil(null);
            staffAccountRepository.save(account);
        }
    }
}
