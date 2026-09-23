package com.carland.carland_auth.service.interfaces;


public interface SMSService {
    void sendSms(Long userId, String acceptLanguage);

    /** Send a raw OTP message to a phone (newUsers flow; code not read from DB). */
    void sendOtpToPhone(String phoneNumber, String otpCode, String acceptLanguage);

    /** Arbitrary SMS text. Do not log {@code message}. */
    void sendTextToPhone(String phoneNumber, String message);
}
