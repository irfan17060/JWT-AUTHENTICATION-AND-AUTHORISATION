package com.irfan.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

@Service
@Slf4j
public class JWTService {

    private static final String SECRET_KEY = "Jh13q8rgZBnv0qpRxXr2fPc8y5X8utd1ez/i4CufLgTPV0K6p3/c9C8esaGEiNyO";

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsTFunction) {
        final Claims claims = extractAllClaims(token);
        return claimsTFunction.apply(claims);
    }

    private Claims extractAllClaims(String token) {

        Claims claims;
        try {
            claims = Jwts.parserBuilder().
                    setSigningKey(getSigningKey()) //when we try to create or generate or to decode a token we need to use the signing key
                    .build()
                    .parseClaimsJwt(token)
                    .getBody();
        } catch (Exception e) {
            log.info("Could not get all claims Token {}", e.getMessage());
            claims = null;
        }
        return claims;

    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
