package com.irfan.security.auth;

import com.irfan.security.model.Role;
import com.irfan.security.model.User;
import com.irfan.security.repo.UserRepo;
import com.irfan.security.service.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepo userRepo;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {

        boolean isPresent = userRepo.findByEmail(request.getEmail()).isPresent();
        var user = isPresent
                ? userRepo.findByEmail(request.getEmail()).get()
                : User.builder()
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        var savedUser = isPresent ? user : userRepo.save(user);

        log.info("saved user {}", savedUser.getEmail());

        var jwtToken = jwtService.buildToken(user);

        return AuthenticationResponse.builder().token(jwtToken).build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        authenticationManager.authenticate
                (new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        var user = userRepo.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.buildToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
