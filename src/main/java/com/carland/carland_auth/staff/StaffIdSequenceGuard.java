package com.carland.carland_auth.staff;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * If Hibernate created {@code staff_account_id_seq} at 1, lift it before the first staff row.
 * Does not read or write {@code users}.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class StaffIdSequenceGuard implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public void run(ApplicationArguments args) {
        try {
            Long count = jdbcTemplate.queryForObject("select count(*) from staff_accounts", Long.class);
            if (count != null && count > 0) {
                return;
            }
            Long last = jdbcTemplate.queryForObject(
                    "select last_value from staff_account_id_seq", Long.class);
            if (last != null && last < StaffIds.MIN_ID) {
                jdbcTemplate.queryForObject(
                        "select setval('staff_account_id_seq', 99999999, true)", Long.class);
                log.info("STAFF_ID_SEQ_LIFTED next>={}", StaffIds.MIN_ID);
            }
        } catch (Exception ex) {
            log.warn("STAFF_ID_SEQ_CHECK_SKIPPED reason={}", ex.getClass().getSimpleName());
        }
    }
}
