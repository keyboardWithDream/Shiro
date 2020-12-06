package com.study.springboot.dao;

import com.study.springboot.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 19:38
 */
@SpringBootTest
public class UserDaoTest {

    @Autowired
    UserDao userDao;

    @Test
    void queryUserByUsername() {
        User user = userDao.queryUserByUsername("admin");
        System.out.println(user);
    }
}
