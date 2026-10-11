package com.carland.carland_auth.repository;

import com.carland.carland_auth.entity.StaffOtp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface StaffOtpRepository extends JpaRepository<StaffOtp, Long> {

    StaffOtp findTopByStaffAccountIdAndStatusOrderByCreatedAtDesc(Long staffAccountId, String status);

    List<StaffOtp> findAllByStaffAccountIdAndStatus(Long staffAccountId, String status);
}
