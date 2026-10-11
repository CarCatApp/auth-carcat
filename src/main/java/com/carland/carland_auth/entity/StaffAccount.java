package com.carland.carland_auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

/**
 * Partner-panel login. Separate from {@code users} so a customer row is never read or written here.
 * Ids start at {@code 100000000}.
 */
@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "staff_accounts")
public class StaffAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "staff_account_seq")
    @SequenceGenerator(
            name = "staff_account_seq",
            sequenceName = "staff_account_id_seq",
            initialValue = 100_000_000,
            allocationSize = 1
    )
    Long id;

    @Column(nullable = false, unique = true, length = 32)
    String phoneNumber;

    @Column(unique = true, length = 128)
    String email;

    /** BCrypt hash. Never the customer {@code password} or {@code pin_hash} column. */
    @Column(name = "staff_password", nullable = false, length = 128)
    String staffPassword;

    @Column(nullable = false, length = 32)
    String role;

    @Column(nullable = false, length = 32)
    String status;

    String name;
    String surname;

    @Builder.Default
    Integer failedAttempts = 0;

    LocalDateTime lastFailedAt;

    LocalDateTime lockedUntil;

    LocalDateTime createdAt;

    LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
        if (failedAttempts == null) {
            failedAttempts = 0;
        }
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
