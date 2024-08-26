package dev.lampirg.loginkey.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @PostMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/jojo")
    public String forJojo() {
        return "JoJo Bizzare Adventure";
    }

    @PostMapping("/protected")
    public String protectedPage() {
        return "It's me! PROTECTED DIO!";
    }

    @GetMapping("/hello")
    public String hello() {
        return "hello!";
    }

    @GetMapping
    public String home() {
        return "redirect:/hello";
    }
}
