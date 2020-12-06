package com.study.springboot.dao;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Set;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 19:51
 */
@SpringBootTest
public class RoleDaoTest {

    @Autowired
    RoleDao roleDao;

    @Test
    void queryRoleNamesByUsername() {
        Set<String> roleNames = roleDao.queryRoleNamesByUsername("admin");
        System.out.println(roleNames);
    }
}
