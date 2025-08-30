package com.example.mockuserservice.controller;

import com.example.mockuserservice.model.AuthRequest;
import com.example.mockuserservice.model.UserInfo;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

@RestController
@RequestMapping("/users")
public class UserController {

    @PostMapping("/validate")
    public UserInfo validateUser(@RequestBody AuthRequest request) {
        if ("john".equals(request.getUsername()) && "password".equals(request.getPassword())) {
            UserInfo user = new UserInfo();
            user.setUsername("john");
            user.setRoles(Arrays.asList("ROLE_USER"));
            return user;
        }
        return null;
    }
}
