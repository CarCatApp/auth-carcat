package com.carland.carland_auth.controller;


import com.carland.carland_auth.dto.request.UserRequest;
import com.carland.carland_auth.dto.response.AuthenticationResponse;
import com.carland.carland_auth.dto.response.NameSurname;
import com.carland.carland_auth.dto.response.UserListItem;
import com.carland.carland_auth.dto.response.UserResponse;
import com.carland.carland_auth.entity.User;
import com.carland.carland_auth.enums.EnumMessagesLangValues;
import com.carland.carland_auth.exceptions.MissingFieldException;
import com.carland.carland_auth.jwt.JWTService;
import com.carland.carland_auth.repository.UserRepository;
import com.carland.carland_auth.service.interfaces.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;


@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor

public class UserController {
    private final UserService userService;
    private final JWTService jwtService;
    private final UserRepository userRepository;




    @GetMapping("/getNameSurname")
    public NameSurname getNameSurname(@RequestParam Long userId) {


        User user = userRepository.findById(userId).orElse(User.builder()
                .name("None")
                .surname("None")
                .build());
        return NameSurname.builder()
                .name(user.getName())
                .surname(user.getSurname())
                .phoneNumber(user.getPhoneNumber())
                .build();
    }

    /**
     * Internal endpoint — carland_service admin paneli için kullanıcı listesi.
     * pin ve role alanları bilerek dahil edilmez.
     * from/to (ISO yyyy-MM-dd) verilirse createdAt'e göre filtreler, to günü dahildir.
     */
    @GetMapping("/list")
    public List<UserListItem> getUserList(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to
    ) {

        List<User> users;

        if (from == null && to == null) {
            users = userRepository.findAll(Sort.by("id"));
        } else {
            LocalDateTime fromDt = (from != null ? from : LocalDate.of(1970, 1, 1)).atStartOfDay();
            LocalDateTime toDtExclusive = (to != null ? to : LocalDate.of(9999, 12, 30)).plusDays(1).atStartOfDay();
            users = userRepository.findAllByCreatedAtGreaterThanEqualAndCreatedAtLessThanOrderByIdAsc(fromDt, toDtExclusive);
        }

        return users.stream()
                .map(user -> UserListItem.builder()
                        .id(user.getId())
                        .createdAt(user.getCreatedAt())
                        .phoneNumber(user.getPhoneNumber())
                        .status(user.getStatus())
                        .name(user.getName())
                        .surname(user.getSurname())
                        .build())
                .toList();
    }

    /** Legacy register. */
    @PostMapping({"/register", "/authentication"})
    public AuthenticationResponse register(@RequestBody UserRequest request,
                                           @RequestParam String role,
                                           @RequestHeader("Accept-Language") String acceptLanguage) {
        return userService.authenticate(request, role, acceptLanguage);
    }

    /** Legacy set password; camelCase + /set/pin kept as aliases (Postman / old clients). */
    @PutMapping({"/set/password", "/set/pin", "/setPassword"})
    public UserResponse setPassword(@Valid @RequestBody UserRequest userRequest,
                                    @RequestHeader("Authorization") String authenticationToken,
                                    @RequestHeader("Accept-Language") String acceptLanguage) {


        Long userId = jwtService.extractUserIdFromAuthenticationToken(authenticationToken);
        return userService.setPin(userRequest, userId, acceptLanguage);
    }

    @PostMapping("/login")
    public UserResponse login(@RequestBody UserRequest request,
                              @RequestHeader("Accept-Language") String acceptLanguage) {

        return userService.login(request, acceptLanguage);
    }

    @PostMapping("/refresh")
    public UserResponse refreshToken(@RequestHeader("Authorization") String refreshToken,
                                     @RequestHeader("Accept-Language") String acceptLanguage) {

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new MissingFieldException(EnumMessagesLangValues.REFRESH_TOKEN_MISSING.getMessageByLang(acceptLanguage));
        }
        Long userId = jwtService.extractUserIdFromRefreshToken(refreshToken);
        return userService.refresh(userId, refreshToken, acceptLanguage);
    }

    /** Legacy forgot-password entry; camelCase + /update/pin kept as aliases. */
    @PutMapping({"/update/password", "/update/pin", "/updatePassword"})
    public AuthenticationResponse updatePassword(@RequestBody UserRequest userRequest,
                                                 @RequestHeader("Accept-Language") String acceptLanguage) {
        return userService.updatePin(userRequest, acceptLanguage);
    }

    @PutMapping("/delete")
    public UserResponse deleteUser(@RequestHeader("Authorization") String accessToken,
                                   @RequestHeader("Accept-Language") String acceptLanguage) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new MissingFieldException(EnumMessagesLangValues.ACCESS_TOKEN_MISSING.getMessageByLang(acceptLanguage));
        }

        String cutToken = accessToken.substring(7);
        if (!jwtService.isAccessTokenValid(cutToken)) {
            throw new RuntimeException(EnumMessagesLangValues.ACCESS_TOKEN_MISSING.getMessageByLang(acceptLanguage));
        }
        Long userId = jwtService.extractUserId(cutToken);
        return userService.deleteUser(userId, acceptLanguage);
    }

}
