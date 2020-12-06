package com.study.springboot.dao;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Set;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 20:06
 */
@SpringBootTest
public class PermissionsDaoTest {

    @Autowired
    PermissionsDao permissionsDao;

    @Test
    void queryPermissionsByUsername() {
        Set<String> permissionsSet = permissionsDao.queryPermissionsByUsername("test");
        System.out.println(permissionsSet);
    }
}
