package com.carland.carland_auth.exceptions;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.stream.Collectors;

@RestControllerAdvice
@RequiredArgsConstructor
@Slf4j
public class CustomExceptionHandler {

private final ObjectMapper objectMapper;



    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ResponseException> handleValidationException(MethodArgumentNotValidException ex) {
        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
                .collect(Collectors.joining(", "));

        ResponseException responseException = ResponseException.builder()
                .error("Validation input error")
                .message(errorMessage)
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .build();

        return new ResponseEntity<>(responseException, HttpStatus.BAD_REQUEST);
    }


    @ExceptionHandler(HttpMessageConversionException.class)
    public ResponseEntity<ResponseException> handleMissingBodyException(HttpMessageConversionException ex) {
        ResponseException responseException=ResponseException.builder()
                .error("Body is required")
                .message("Məlumatlar əksikdir!")
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MsmTransactionException.class)
    public ResponseEntity<ResponseException> handleMsmTransactionException(MsmTransactionException ex) {
        ResponseException responseException=ResponseException.builder()
                .error("Otp message error")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.BAD_REQUEST);
    }
    @ExceptionHandler(InvalidStatusException .class)
    public ResponseEntity<ResponseException> handleUserStatusException(InvalidStatusException  ex) {
        ResponseException responseException=ResponseException.builder()
                .error("Invalid user status")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.BAD_REQUEST);
    }


    @ExceptionHandler(ResourceNotFoundException .class)
    public ResponseEntity<ResponseException> handleResourceNotFoundException(ResourceNotFoundException  ex) {
        ResponseException responseException=ResponseException.builder()
                .error("Resource not found error")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.NOT_FOUND.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(InvalidOtpCodeException .class)
    public ResponseEntity<ResponseException> handleInvalidOtpCodeException(InvalidOtpCodeException  ex) {
        ResponseException responseException=ResponseException.builder()
                .error("Invalid Otp error")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ExpiredOtpException.class)
    public ResponseEntity<ResponseException> handleExpiredOtpException(ExpiredOtpException ex) {
        ResponseException responseException=ResponseException.builder()
                .error("Expired Otp error")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(UsernameAlreadyExistException.class)
    public ResponseEntity<ResponseException> handleUsernameAlreadyExistException(UsernameAlreadyExistException ex) {
        ResponseException responseException=ResponseException.builder()
                .error("User already exists")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.CONFLICT.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(MissingFieldException.class)
    public ResponseEntity<ResponseException> handleMissingFieldException(MissingFieldException ex) {
        ResponseException responseException=ResponseException.builder()
                .error("Missed required fields")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ResponseException> handleUserNotFoundException(UserNotFoundException ex) {
        ResponseException responseException=ResponseException.builder()
                .error("User not found")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.NOT_FOUND.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(WrongPasswordException.class)
    public ResponseEntity<ResponseException> handleWrongPasswordException(WrongPasswordException ex) {
        ResponseException responseException=ResponseException.builder()
                .error("Wrong password")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(WeakPinException.class)
    public ResponseEntity<ResponseException> handleWeakPinException(WeakPinException ex) {
        ResponseException responseException = ResponseException.builder()
                .error("Weak PIN")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(PinLockedException.class)
    public ResponseEntity<ResponseException> handlePinLockedException(PinLockedException ex) {
        ResponseException responseException = ResponseException.builder()
                .error("LOGIN_LOCKED")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.TOO_MANY_REQUESTS.value())
                .lockedUntil(ex.getLockedUntil())
                .remainingSeconds(ex.getRemainingSeconds())
                .retryAfter(ex.getRemainingSeconds())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.TOO_MANY_REQUESTS);
    }

    @ExceptionHandler(AuthApiException.class)
    public ResponseEntity<ResponseException> handleAuthApiException(AuthApiException ex) {
        ResponseException.ResponseExceptionBuilder builder = ResponseException.builder()
                .error(ex.getError())
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(ex.getStatus().value());
        if (ex.getLockedUntil() != null) {
            builder.lockedUntil(ex.getLockedUntil())
                    .remainingSeconds(ex.getRemainingSeconds())
                    .retryAfter(ex.getRemainingSeconds());
        }
        return new ResponseEntity<>(builder.build(), ex.getStatus());
    }

    @ExceptionHandler(RefreshTokenNotSetException.class)
    public ResponseEntity<ResponseException> handleRefreshTokenNotSetException(RefreshTokenNotSetException ex) {
        ResponseException responseException=ResponseException.builder()
                .error("Refresh token not found")
                .message(ex.getMessage())
                .timeStamp(LocalDateTime.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .build();
        return new ResponseEntity<>(responseException, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(FeignException.class)
    public ResponseEntity<ResponseException> handleFeignException(FeignException ex) {
        String feignError = ex.contentUTF8();
        String error = "Unexpected error";
        String message = "Bilinməyən daxili xəta";

        try {
            JsonNode jsonNode = objectMapper.readTree(feignError);
            if (jsonNode.has("error") || jsonNode.has("message")) {
                error = jsonNode.get("error").asText();
                message = jsonNode.get("message").asText();
            }
        } catch (IOException e) {
            log.error("IO  error message : {}", e.getMessage());
        }

        ResponseException responseException = ResponseException.builder()
                .error(error)
                .message(message)
                .timeStamp(LocalDateTime.now())
                .status(ex.status())
                .build();

        log.error("error message is : {} ", responseException.getMessage());
        return new ResponseEntity<>(responseException, HttpStatus.valueOf(ex.status()));
    }


}
