package com.study.springboot.service;

import com.study.springboot.dao.UserDao;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Random;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 16:16
 */
@Service
public class UserServiceImpl {

    @Autowired
    private UserDao userDao;

    public void checkLogin(String username, String password, boolean rememberMe) {
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        token.setRememberMe(rememberMe);
        subject.login(token);
    }

    public void register(String username, String password) {
        //加盐加密
        String salt = String.valueOf(new Random().nextInt(90000) + 10000);
        Md5Hash md5Hash = new Md5Hash(password, salt, 1);
        userDao.saveUser(username, md5Hash.toString(), salt);
    }

    public void deleteUserByUsername(String username) {
        userDao.deleteUserByUsername(username);
    }
}
