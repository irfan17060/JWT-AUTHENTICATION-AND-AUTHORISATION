package com.irfan.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin-controller")
public class AdminController {

    @GetMapping
    public ResponseEntity<String> testMethod(){
        return ResponseEntity.ok("Hello from secured endpoint");
    }
}
