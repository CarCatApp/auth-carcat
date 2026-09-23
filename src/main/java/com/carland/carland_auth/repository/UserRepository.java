package com.carland.carland_auth.repository;

import com.carland.carland_auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {


    User findByIdAndStatus(Long userId, String status);

    List<User> findAllByCreatedAtGreaterThanEqualAndCreatedAtLessThanOrderByIdAsc(
            LocalDateTime from, LocalDateTime toExclusive);

    User findByPhoneNumber(String phoneNumber);
    User findByPhoneNumberAndStatus(String phoneNumber, String  status);

    User findByEmailIgnoreCase(String email);

    @Query("SELECT u FROM User u JOIN u.refreshTokens rt WHERE rt.id = :refreshTokenId")
    User findByRefreshTokenId(@Param("refreshTokenId") Long refreshTokenId);

}
