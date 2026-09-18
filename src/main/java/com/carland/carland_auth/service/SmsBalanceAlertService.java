package com.carland.carland_auth.service;

import com.carland.carland_auth.entity.SmsBalanceAlert;
import com.carland.carland_auth.feign.LsimFeign;
import com.carland.carland_auth.repository.SmsBalanceAlertRepository;
import com.carland.carland_auth.util.Md5Util;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * After OTP SMS: check LSIM balance; alert ops phones once when remaining hits 1500/1000/500.
 * Failures must never break the user OTP flow.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SmsBalanceAlertService {

    private static final List<Integer> DEFAULT_THRESHOLDS = List.of(1500, 1000, 500);
    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("dd.MM.yyyy");

    private final LsimFeign lsimFeign;
    private final SmsBalanceAlertRepository smsBalanceAlertRepository;
    private final ObjectMapper objectMapper;

    @Value("${lsim.api.login}")
    private String login;

    @Value("${lsim.api.password}")
    private String password;

    @Value("${lsim.api.sender}")
    private String sender;

    @Value("${lsim.balance-alert.phones}")
    private String alertPhonesCsv;

    @Value("${lsim.balance-alert.thresholds:1500,1270,1000,500}")
    private String thresholdsCsv;

    public void checkAndAlertAfterOtpSend() {
        try {
            int balance = fetchBalance();
            List<Integer> thresholds = parseThresholds();
            for (Integer threshold : thresholds) {
                if (balance > threshold) {
                    smsBalanceAlertRepository.findById(threshold).ifPresent(smsBalanceAlertRepository::delete);
                    continue;
                }
                if (balance == threshold && smsBalanceAlertRepository.findById(threshold).isEmpty()) {
                    sendAlert(threshold);
                    smsBalanceAlertRepository.save(SmsBalanceAlert.builder()
                            .threshold(threshold)
                            .alertedAt(LocalDateTime.now())
                            .build());
                }
            }
        } catch (Exception ex) {
            log.warn("LSIM balance alert skipped (OTP flow continues): {}", ex.getMessage());
        }
    }

    private int fetchBalance() throws Exception {
        String passMd5 = Md5Util.md5(password);
        String key = Md5Util.md5(passMd5 + login);
        String raw = lsimFeign.getBalance(login, key);
        log.info("LSIM balance response: {}", raw);
        JsonNode node = objectMapper.readTree(raw);
        if (node.has("errorCode") && !node.get("errorCode").isNull()
                && !node.get("errorCode").asText().isBlank()) {
            throw new IllegalStateException("LSIM balance errorCode=" + node.get("errorCode").asText());
        }
        if (!node.has("obj") || node.get("obj").isNull()) {
            throw new IllegalStateException("LSIM balance missing obj");
        }
        return node.get("obj").asInt();
    }

    private void sendAlert(int remaining) {
        String text = LocalDate.now().format(DATE_FMT) + " -> qalan sms balans " + remaining;
        String passMd5 = Md5Util.md5(password);
        for (String phone : parsePhones()) {
            try {
                String number = phone.startsWith("+") ? phone.substring(1) : phone;
                String raw = passMd5 + login + text + number + sender;
                String key = Md5Util.md5(raw);
                String response = lsimFeign.sendSms(login, number, text, sender, key, true);
                log.info("LSIM balance alert to {} ({}): {}", phone, remaining, response);
            } catch (Exception ex) {
                log.warn("LSIM balance alert SMS failed for {}: {}", phone, ex.getMessage());
            }
        }
    }

    private List<String> parsePhones() {
        return Arrays.stream(alertPhonesCsv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    private List<Integer> parseThresholds() {
        try {
            List<Integer> parsed = Arrays.stream(thresholdsCsv.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(Integer::valueOf)
                    .sorted((a, b) -> Integer.compare(b, a))
                    .collect(Collectors.toList());
            return parsed.isEmpty() ? DEFAULT_THRESHOLDS : parsed;
        } catch (Exception ex) {
            return DEFAULT_THRESHOLDS;
        }
    }
}
