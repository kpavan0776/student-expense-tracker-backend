
package com.example.demo;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final JdbcTemplate jdbc;
    private final BCryptPasswordEncoder encoder =
            new BCryptPasswordEncoder();
    private final JwtService jwtService;

    public AuthController(JdbcTemplate jdbc, JwtService jwtService) {
        this.jdbc = jdbc;
        this.jwtService = jwtService;
    }

    // Test endpoint
    @GetMapping("/api/auth-test")
    public Map<String, String> authTest() {
        return Map.of("message", "Fresh authentication setup ready");
    }

    // Sign up
    @PostMapping("/api/signup")
    public ResponseEntity<Map<String, Object>> signup(
            @RequestBody Map<String, String> body) {

        String name = body.get("name");
        String email = body.get("email");
        String password = body.get("password");

        if (name == null || name.isBlank()
                || email == null || email.isBlank()
                || password == null || password.length() < 6) {
            return response(
                    HttpStatus.BAD_REQUEST,
                    "Enter your name, email, and a password of at least 6 characters"
            );
        }

        name = name.trim();
        email = email.trim().toLowerCase(Locale.ROOT);

        try {
            Integer count = jdbc.queryForObject(
                    "SELECT COUNT(*) FROM users WHERE email = ?",
                    Integer.class,
                    email
            );

            if (count != null && count > 0) {
                return response(
                        HttpStatus.CONFLICT,
                        "An account with this email already exists"
                );
            }

            jdbc.update(
                    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    name,
                    email,
                    encoder.encode(password)
            );

            Integer userId = jdbc.queryForObject(
                    "SELECT id FROM users WHERE email = ?",
                    Integer.class,
                    email
            );

            if (userId == null) {
                return response(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "Account created, but its ID could not be retrieved"
                );
            }

            String token = jwtService.generateToken(userId);

            Map<String, Object> user = new HashMap<>();
            user.put("id", userId);
            user.put("name", name);
            user.put("email", email);

            Map<String, Object> result = new HashMap<>();
            result.put("message", "Account created successfully");
            result.put("token", token);
            result.put("user", user);

            return ResponseEntity.status(HttpStatus.CREATED).body(result);

        } catch (org.springframework.dao.DuplicateKeyException e) {
            return response(
                    HttpStatus.CONFLICT,
                    "An account with this email already exists"
            );
        }
    }

    // Sign in
    @PostMapping("/api/signin")
    public ResponseEntity<Map<String, Object>> signin(
            @RequestBody Map<String, String> body) {

        String email = body.get("email");
        String password = body.get("password");

        if (email == null || email.isBlank()
                || password == null || password.isBlank()) {
            return response(
                    HttpStatus.BAD_REQUEST,
                    "Enter your email and password"
            );
        }

        email = email.trim().toLowerCase(Locale.ROOT);

        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, name, email, password FROM users WHERE email = ?",
                email
        );

        if (rows.isEmpty()) {
            return response(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid email or password"
            );
        }

        Map<String, Object> row = rows.get(0);
        String storedHash = (String) row.get("password");

        if (storedHash == null || !encoder.matches(password, storedHash)) {
            return response(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid email or password"
            );
        }

        int userId = ((Number) row.get("id")).intValue();
        String name = (String) row.get("name");
        String storedEmail = (String) row.get("email");

        String token = jwtService.generateToken(userId);

        Map<String, Object> user = new HashMap<>();
        user.put("id", userId);
        user.put("name", name);
        user.put("email", storedEmail);

        Map<String, Object> result = new HashMap<>();
        result.put("message", "Signed in successfully");
        result.put("token", token);
        result.put("user", user);

        return ResponseEntity.ok(result);
    }

    // Standard error response
    private ResponseEntity<Map<String, Object>> response(
            HttpStatus status,
            String message) {

        return ResponseEntity.status(status)
                .body(Map.of("message", message));
    }
}
