package com.carland.carland_auth.service.interfaces;


import com.carland.carland_auth.dto.request.UserRequest;
import com.carland.carland_auth.dto.response.AuthenticationResponse;
import com.carland.carland_auth.dto.response.UserResponse;

public interface UserService {
    AuthenticationResponse authenticate(UserRequest request, String role, String acceptLanguage);

    UserResponse login(UserRequest request, String acceptLanguage);

    UserResponse refresh(Long userId, String refreshToken, String acceptLanguage);

    UserResponse setPin(UserRequest userRequest, Long userId, String acceptLanguage);

    AuthenticationResponse updatePin(UserRequest userRequest, String acceptLanguage);

    UserResponse deleteUser(Long userId, String acceptLanguage);
}
