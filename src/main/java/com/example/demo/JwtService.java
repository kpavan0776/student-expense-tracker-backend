
package com.example.demo;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey key;

    public JwtService() {
        String secret = System.getenv("JWT_SECRET");

        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException(
                "JWT_SECRET must contain at least 32 characters"
            );
        }

        this.key = Keys.hmacShaKeyFor(
            secret.getBytes(StandardCharsets.UTF_8)
        );
    }

    public String generateToken(int userId) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
            .subject(String.valueOf(userId))
            .issuedAt(new Date(now))
            .expiration(new Date(now + 24 * 60 * 60 * 1000L))
            .signWith(key)
            .compact();
    }

    public int getUserId(String token) {
        Claims claims = Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .getPayload();

        return Integer.parseInt(claims.getSubject());
    }
}
