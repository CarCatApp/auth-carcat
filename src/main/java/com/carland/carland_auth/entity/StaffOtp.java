package com.carland.carland_auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

/**
 * Staff password-reset code. Stores HMAC-SHA256 only, never the plaintext code.
 */
@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "staff_otps")
public class StaffOtp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    @Column(name = "staff_account_id", nullable = false)
    Long staffAccountId;

    @Column(name = "code_hash", nullable = false, length = 64)
    String codeHash;

    @Column(nullable = false, length = 16)
    String status;

    @Builder.Default
    Integer verifyFailCount = 0;

    LocalDateTime createdAt;
}
