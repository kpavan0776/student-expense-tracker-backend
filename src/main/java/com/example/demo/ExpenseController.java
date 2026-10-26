
package com.example.demo;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.JwtException;

@RestController
public class ExpenseController {

    private final JdbcTemplate jdbc;
    private final JwtService jwtService;

    public ExpenseController(JdbcTemplate jdbc, JwtService jwtService) {
        this.jdbc = jdbc;
        this.jwtService = jwtService;
    }

    // Get expenses belonging only to the authenticated user
    @GetMapping("/api/expenses")
    public ResponseEntity<?> getExpenses(
            @RequestHeader(value = "Authorization", required = false)
            String authorization) {

        Integer userId = getAuthenticatedUserId(authorization);

        if (userId == null) {
            return error(HttpStatus.UNAUTHORIZED,
                    "Missing or invalid authentication token");
        }

        List<Map<String, Object>> expenses = jdbc.queryForList(
                "SELECT id, title, amount, category, " +
                "expense_date AS date FROM expenses " +
                "WHERE user_id = ? " +
                "ORDER BY expense_date DESC, id DESC",
                userId
        );

        return ResponseEntity.ok(expenses);
    }

    // Add an expense for the authenticated user
    @PostMapping("/api/expenses")
    public ResponseEntity<?> addExpense(
            @RequestHeader(value = "Authorization", required = false)
            String authorization,
            @RequestBody Map<String, Object> body) {

        Integer userId = getAuthenticatedUserId(authorization);

        if (userId == null) {
            return error(HttpStatus.UNAUTHORIZED,
                    "Missing or invalid authentication token");
        }

        Object titleValue = body.get("title");
        Object amountValue = body.get("amount");
        Object categoryValue = body.get("category");

        String title = titleValue == null
                ? "" : titleValue.toString().trim();

        String category = categoryValue == null
                ? "" : categoryValue.toString().trim();

        Object dateValue = body.get("date");

        if (dateValue == null) {
            dateValue = body.get("expense_date");
        }

        String dateText = dateValue == null
                ? "" : dateValue.toString().trim();

        if (title.isBlank() || title.length() > 150
                || category.isBlank() || category.length() > 100
                || dateText.isBlank() || amountValue == null) {
            return error(HttpStatus.BAD_REQUEST,
                    "Enter a valid title, amount, category, and date");
        }

        BigDecimal amount;

        try {
            amount = new BigDecimal(amountValue.toString());

            if (amount.compareTo(BigDecimal.ZERO) <= 0
                    || amount.scale() > 2
                    || amount.precision() > 10) {
                return error(HttpStatus.BAD_REQUEST,
                        "Amount must be positive and have at most 2 decimal places");
            }
        } catch (NumberFormatException ex) {
            return error(HttpStatus.BAD_REQUEST,
                    "Amount must be a valid number");
        }

        LocalDate expenseDate;

        try {
            expenseDate = LocalDate.parse(dateText);
        } catch (DateTimeParseException ex) {
            return error(HttpStatus.BAD_REQUEST,
                    "Date must use YYYY-MM-DD format");
        }

        jdbc.update(
                "INSERT INTO expenses " +
                "(user_id, title, amount, category, expense_date) " +
                "VALUES (?, ?, ?, ?, ?)",
                userId, title, amount, category, expenseDate
        );

        Map<String, Object> result = new HashMap<>();
        result.put("message", "Expense added successfully");

        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    // Validate the Bearer token and obtain its user ID
    private Integer getAuthenticatedUserId(String authorization) {

        if (authorization == null
                || !authorization.startsWith("Bearer ")) {
            return null;
        }

        String token = authorization.substring(7).trim();

        if (token.isEmpty()) {
            return null;
        }

        try {
            return jwtService.getUserId(token);
        } catch (JwtException | IllegalArgumentException ex) {
            return null;
        }
    }

    private ResponseEntity<Map<String, String>> error(
            HttpStatus status, String message) {

        return ResponseEntity.status(status)
                .body(Map.of("message", message));
    }
}
