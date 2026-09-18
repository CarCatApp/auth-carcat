package com.carland.carland_auth.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum EnumMessagesLangValues {

    MISSING_BODY(
            "Məlumatlar əksikdir!",
            "Missing body!",
            "Данные отсутствуют!"
    ),

    MISSING_FIELDS(
            "Mobil nömrə, ad, soyad, doğum tarixi boş ola bilməz",
            "Mobile number, name, surname, and birth date cannot be empty",
            "Номер телефона, имя, фамилия и дата рождения не могут быть пустыми"
    ),
    USERNAME_ALREADY_EXISTS(
            "Bu nömrə ilə artıq qeydiyyat mövcuddur",
            "An account with this number already exists",
            "Аккаунт с этим номером уже существует"
    ),
    REGISTER_SUCCESS(
            "Qeydiyyat uğurludur",
            "Registration successful",
            "Регистрация прошла успешно"
    ),
    REGISTER_SUCCESS_UPDATED(
            "Qeydiyyat uğurludur (mövcud istifadəçi yeniləndi)",
            "Registration successful (existing user updated)",
            "Регистрация прошла успешно (существующий пользователь обновлён)"
    ),
    MISSING_USER_FIELDS(
            "Telefon nömrəsi və PIN boş ola bilməz",
            "Phone number and PIN cannot be empty",
            "Номер телефона и PIN не могут быть пустыми"
    ),
    USER_NOT_FOUND(
            "İstifadəçi mövcud deyil",
            "User not found",
            "Пользователь не найден"
    ),
    WRONG_PASSWORD(
            "Daxil etdiyiniz PIN yanlışdır.",
            "The PIN you entered is incorrect",
            "Введённый PIN неверный."
    ),
    WEAK_PIN(
            "PIN zəifdir. 4 rəqəmli olmalıdır; bütün rəqəmlər eyni və ya ardıcıl (məs. 1234) ola bilməz.",
            "Weak PIN. It must be 4 digits and not all the same or a sequence (e.g. 1234).",
            "Слабый PIN. Должен состоять из 4 цифр; одинаковые или последовательные (напр. 1234) нельзя."
    ),
    OTP_RATE_LIMITED(
            "Çox sayda OTP sorğusu. Bir az sonra yenidən cəhd edin.",
            "Too many OTP requests. Please try again later.",
            "Слишком много OTP запросов. Попробуйте позже."
    ),
    OTP_RESEND_COOLDOWN(
            "OTP yenidən göndərmək üçün bir az gözləyin.",
            "Please wait before requesting another OTP.",
            "Подождите перед повторным запросом OTP."
    ),
    DEVICE_REQUIRED(
            "deviceToken və platform tələb olunur",
            "deviceToken and platform are required",
            "Требуются deviceToken и platform"
    ),
    AUTH_TOKEN_MISSING(
            "authToken tələb olunur",
            "authToken is required",
            "Требуется authToken"
    ),
    AUTH_TOKEN_INVALID(
            "authToken etibarsızdır və ya vaxtı bitib",
            "authToken is invalid or expired",
            "authToken недействителен или истёк"
    ),

    PIN_LOCKED(
            "Hesab müvəqqəti kilidlənib. Bir az sonra yenidən cəhd edin.",
            "Account is temporarily locked. Please try again later.",
            "Аккаунт временно заблокирован. Попробуйте позже."
    ),
    LOGIN_SUCCESS(
            "Uğurlu giriş",
            "Login successful",
            "Вход выполнен успешно"
    ),
    MISSING_USER_ID(
            "İstifadəçi ID boş ola bilməz",
            "User ID cannot be empty",
            "ID пользователя не может быть пустым"
    ),
    REFRESH_TOKEN_NOT_FOUND(
            "Token tapılmadı",
            "Token not found",
            "Токен не найден"
    ),
    REFRESH_TOKEN_SUCCESS(
            "Token uğurla yeniləndi",
            "Token refreshed successfully",
            "Токен успешно обновлён"
    ),
    INVALID_USER_STATUS(
            "İstifadəçi uyğun statusda deyil",
            "User is not in a valid status",
            "Пользователь имеет недопустимый статус"
    ),
    PASSWORD_SET_SUCCESS(
            "PIN təyin edildi",
            "PIN set successfully",
            "PIN успешно установлен"
    ),
    MISSING_PHONE_NUMBER(
            "Telefon nömrəsi boş ola bilməz",
            "Phone number cannot be empty",
            "Номер телефона не может быть пустым"
    ),
    OTP_SENT(
            "Otp göndərildi",
            "OTP sent",
            "OTP отправлен"
    ),

    CARLAND_SERVICE_ERROR(
            "Xəta baş verdi. Bir az sonra yenidən cəhd edin",
            "An error occurred. Please try again later",
            "Произошла ошибка. Попробуйте позже"
    ),

    INVALID_OTP_CODE(
            "OTP kod yanlışdır",
            "OTP code is incorrect",
            "Неверный код OTP"
    ),
    ACCESS_TOKEN_MISSING(
            "Access token göndərilmədi",
            "Access token is missing",
            "Access токен не был отправлен"
    ),


    REFRESH_TOKEN_MISSING(
            "Refresh token göndərilmədi",
            "Refresh token is missing",
            "Отсутствует refresh токен"
    ),

    AUTHENTICATION_TOKEN_EXPIRED(
            "Authentication tokenin vaxtı keçib",
            "Authentication token expired",
            "Срок действия токена аутентификации истек"
    ),
    EXPIRED_OTP(
            "OTP aktivlik müddəti bitmişdir",
            "The OTP validity period has expired.",
            "Срок активности OTP истёк"
    ),
    OTP_VERIFIED_SUCCESS(
            "Otp təstiqləmə uğurla başa çatdı",
            "OTP verification completed successfully",
            "Проверка OTP успешно завершена"
    ),
    SUCCESS(
            "Uğurla tamamlandı",
            "Success",
            "Успешно"
    ),
    OTP_NOT_FOUND(
            "Şərtlərə uyğun OTP tapılmadı",
            "OTP not found for the given conditions",
            "OTP не найдено для указанных условий"
    ),
    MSM_TRANSACTION_ERROR(
            "Xəta baş verdi. Bir az sonra yenidən cəhd edin",
            "An error occurred. Please try again later",
            "Произошла ошибка. Попробуйте позже"
    ),

    TOKEN_INVALID(
            "Token düzgün deyil və ya vaxtı keçib",
            "Token is invalid or expired",
            "Токен недействителен или истек"),

    TOKEN_MISSING(
            "Token yoxdur və ya düzgün deyil",
            "Token is missing or invalid",
            "Токен отсутствует или недействителен"),

    TOKEN_EXPIRED(
            "Token müddəti bitib",
            "Token expired",
            "Token expired"),
    USER_SUCCESSFULLY_DELETED(
            "İstifadəçi silindi",
            "User deleted",
            "Пользователь удалено"
    ),
    INVALID_ROLE_PERMISSION(
            "Əməliyyat üçün səlahiyyətiniz yoxdur!",
            "You dont have permission for operation!",
            "У вас нет прав для операции!"
    ),
    STAFF_PASSWORD_TOO_SHORT(
            "Şifrə ən azı 8 simvol olmalıdır",
            "Password must be at least 8 characters",
            "Пароль должен быть не короче 8 символов"
    ),
    STAFF_CURRENT_PASSWORD_REQUIRED(
            "Cari şifrə tələb olunur",
            "Current password is required",
            "Требуется текущий пароль"
    );


    private final String azMessage;
    private final String enMessage;
    private final String ruMessage;

    public String getMessageByLang(String lang) {
        if (lang == null) return azMessage;
        return switch (lang.toLowerCase()) {
            case "az" -> azMessage;
            case "en" -> enMessage;
            case "ru" -> ruMessage;
            default -> azMessage;
        };
    }
}
