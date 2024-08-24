package dev.lampirg.loginkey.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @PostMapping("/login")
    public void login() {
        // Authenticating
    }

    @PostMapping("/jojo")
    public void forJojo() {
        // Authenticating
    }

    @PostMapping("/protected")
    public void protectedPage() {
        // Authenticating
    }

    @GetMapping
    public String hello() {
        return "hello!";
    }
}
