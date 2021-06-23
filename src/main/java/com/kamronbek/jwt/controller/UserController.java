package com.kamronbek.jwt.controller;

import com.kamronbek.jwt.dto.AuthenticationResponse;
import com.kamronbek.jwt.dto.RegistrationRequest;
import com.kamronbek.jwt.service.UserService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/v1/users")
@AllArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;


    @PostMapping("/authenticate")
    public AuthenticationResponse authenticate() {
        return userService.authenticate();
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegistrationRequest request) {
        return userService.register(request);
    }
}
