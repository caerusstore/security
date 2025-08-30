package com.example.authservice.model;

import java.util.List;

public class UserInfo {
    private String username;
    private List<String> roles;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public List<String> getRoles() { return roles; }
    public void setRoles(List<String> roles) { this.roles = roles; }
}
