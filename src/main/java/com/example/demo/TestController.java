package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/")
    public String home() {
        return "Student Expense Tracker Backend is running!";
    }

    @GetMapping("/api/test")
    public String test() {
        return "API is working!";
    }
}
