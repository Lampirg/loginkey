package dev.lampirg.loginkey.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @PostMapping("/login")
    public void hello() {
        // Authenticating
    }
}
