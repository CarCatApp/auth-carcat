package com.carland.carland_auth.repository;

import com.carland.carland_auth.entity.StaffAccount;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StaffAccountRepository extends JpaRepository<StaffAccount, Long> {

    StaffAccount findByPhoneNumber(String phoneNumber);

    StaffAccount findByEmailIgnoreCase(String email);

    boolean existsByPhoneNumber(String phoneNumber);

    boolean existsByEmailIgnoreCase(String email);
}
