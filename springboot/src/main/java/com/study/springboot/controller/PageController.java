package com.study.springboot.controller;

import org.apache.shiro.authz.annotation.RequiresUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 15:56
 */
@Controller
public class PageController {

    @RequestMapping("/login.html")
    public String login() {
        return "login";
    }

    @RequestMapping("/")
    public String welcome() {
        return "login";
    }

    @RequiresUser
    @RequestMapping("/index.html")
    public String index() {
        return "index";
    }

    @RequestMapping("/del.html")
    public String del() {
        return "del";
    }

    @RequestMapping("/lessPermission.html")
    public String lessPermission() {
        return "lessPermission";
    }
}
