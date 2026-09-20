package com.carland.carland_auth.config;

import com.carland.carland_auth.entity.User;
import com.carland.carland_auth.enums.UserRoles;
import com.carland.carland_auth.enums.UserStatus;
import com.carland.carland_auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * tr: Panel admin kullanıcısı yoksa auth DB'ye ekler. Phone/PIN env'den gelir.
 * en: Inserts the panel admin user when missing. Phone/PIN come from env.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PanelAdminUserBootstrap implements ApplicationRunner {

    private final UserRepository userRepository;
    private final Argon2PasswordEncoder argon2PasswordEncoder;

    @Value("${carland.admin.panel-phone}")
    private String panelAdminPhone;

    @Value("${carland.admin.legacy-panel-phone:+994000000000}")
    private String legacyPanelAdminPhone;

    @Value("${carland.admin.panel-pin}")
    private String panelAdminPin;

    @Override
    public void run(ApplicationArguments args) {
        User existing = userRepository.findByPhoneNumber(panelAdminPhone);
        boolean dirty = false;
        if (existing == null) {
            existing = userRepository.findByPhoneNumber(legacyPanelAdminPhone);
            if (existing != null) {
                existing.setPhoneNumber(panelAdminPhone);
                dirty = true;
            }
        }
        if (existing != null) {
            if ("ADMIN".equalsIgnoreCase(existing.getRole())
                    || "SUPER_ADMIN".equalsIgnoreCase(existing.getRole())) {
                existing.setRole(UserRoles.USER.name());
                dirty = true;
            }
            if (!UserStatus.ACTIVE.name().equalsIgnoreCase(existing.getStatus())) {
                existing.setStatus(UserStatus.ACTIVE.name());
                dirty = true;
            }
            if (existing.getPinHash() == null || existing.getPinHash().isBlank()) {
                existing.setPinHash(argon2PasswordEncoder.encode(panelAdminPin));
                dirty = true;
            }
            if (dirty) {
                userRepository.save(existing);
                log.info("Panel admin user updated: {}", panelAdminPhone);
            }
            return;
        }
        userRepository.save(User.builder()
                .phoneNumber(panelAdminPhone)
                .pinHash(argon2PasswordEncoder.encode(panelAdminPin))
                .role(UserRoles.USER.name())
                .status(UserStatus.ACTIVE.name())
                .name("Panel")
                .surname("Admin")
                .createdAt(LocalDateTime.now())
                .failedPinAttempts(0)
                .build());
        log.info("Panel admin user created: {}", panelAdminPhone);
    }
}
