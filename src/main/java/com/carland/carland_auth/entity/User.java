package com.carland.carland_auth.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;


@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    @Column(nullable = false, unique = true)
    String phoneNumber;

    @Column(unique = true, length = 128)
    String email;

    /**
     * Legacy BCrypt password hash (column password).
     * Nullable for NewUsers-only accounts. Drop this column after full PIN migration.
     */
    @Column(name = "password")
    String pin;

    /**
     * NewUsers Argon2id PIN hash. Null = no PIN set yet (legacy or unfinished signup).
     */
    @Column(name = "pin_hash")
    String pinHash;

    @JsonIgnore
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    @ToString.Exclude
    List<RefreshToken> refreshTokens = new ArrayList<>();
    LocalDateTime createdAt;
    String status;
    String role;
    String name;
    String surname;

    @Builder.Default
    Integer failedPinAttempts = 0;

    LocalDateTime pinLockedUntil;

    LocalDateTime lastFailedPinAt;
}
