package com.carland.carland_auth.feign;

import com.carland.carland_auth.staff.dto.StaffAuditRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "carlandBookingClient", url = "${carland.api.url}")
public interface CarlandBookingFeign {

    @PostMapping("/api/v1/internal/booking/staff/activate")
    void activateStaff(@RequestHeader("X-Internal-Token") String internalToken,
                       @RequestParam("userId") Long userId);

    @PostMapping("/api/v1/internal/booking/staff/audit")
    void auditStaff(@RequestHeader("X-Internal-Token") String internalToken,
                    @RequestBody StaffAuditRequest request);
}
