package com.study.springboot.controller;

import com.study.springboot.service.UserServiceImpl;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 16:13
 */
@Controller
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserServiceImpl service;

    @RequestMapping("/login")
    public String login(String username, String password, boolean rememberMe) {
        try {
            service.checkLogin(username, password, rememberMe);
            return "index";
        } catch (Exception e) {
            return "login";
        }
    }

    @RequestMapping("/register")
    public String register(String username, String password) {
        service.register(username, password);
        return "login";
    }

    @RequiresRoles("admin")
    @PostMapping("/del")
    public String delUser(String username) {
        service.deleteUserByUsername(username);
        return "index";
    }
}
