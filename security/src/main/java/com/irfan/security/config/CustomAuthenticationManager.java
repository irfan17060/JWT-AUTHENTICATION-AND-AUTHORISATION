package com.irfan.security.config;


import com.irfan.security.model.User;
import com.irfan.security.repo.UserRepo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
public class CustomAuthenticationManager implements AuthenticationManager {

    @Autowired
    private  UserRepo userRepo;
    @Autowired
    private  PasswordEncoder passwordEncoder;



    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Optional<User> user = userRepo.findByEmail(authentication.getName());
        if (user.isPresent()) {
            if (passwordEncoder.matches(authentication.getCredentials().toString(), user.get().getPassword())) {
                List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();

                return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), grantedAuthorityList);
            } else {
                throw new BadCredentialsException("Wrong Password");
            }
        } else {
            throw new BadCredentialsException("Wrong UserName");
        }
    }
}
