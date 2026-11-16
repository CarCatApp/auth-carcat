package com.carland.carland_auth.repository;

import com.carland.carland_auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    RefreshToken findTopByUserIdOrderByCreatedAtDesc(Long userId);

    RefreshToken findTopByUserIdAndRevokedAtIsNullOrderByCreatedAtDesc(Long userId);

    /** Presented refresh token must match any active row — not only the latest. */
    RefreshToken findByUserIdAndTokenAndRevokedAtIsNull(Long userId, String token);

    RefreshToken findByUserIdAndToken(Long userId, String token);

    List<RefreshToken> findAllByUserIdAndRevokedAtIsNull(Long userId);

    // flushAutomatically: pending User.pinHash/status must hit DB before clearAutomatically drops the session.
    // Caller MUST pass non-blank keepDeviceId; null keep previously revoked ALL sessions.
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update RefreshToken r set r.revokedAt = :now where r.user.id = :userId and r.revokedAt is null "
            + "and (r.deviceId is null or r.deviceId <> :keepDeviceId)")
    int revokeAllExceptDevice(@Param("userId") Long userId,
                              @Param("keepDeviceId") String keepDeviceId,
                              @Param("now") LocalDateTime now);

    /** Same-device login rotate: retire prior refresh rows for this device only. */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update RefreshToken r set r.revokedAt = :now where r.user.id = :userId and r.revokedAt is null "
            + "and r.deviceId = :deviceId")
    int revokeByUserIdAndDeviceId(@Param("userId") Long userId,
                                  @Param("deviceId") String deviceId,
                                  @Param("now") LocalDateTime now);
}
