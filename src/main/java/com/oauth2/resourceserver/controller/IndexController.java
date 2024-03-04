package com.oauth2.resourceserver.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/api/user")
    public Authentication user(Authentication authentication) {
        System.out.println("authentication = " + authentication);
        return authentication;
    }
}
