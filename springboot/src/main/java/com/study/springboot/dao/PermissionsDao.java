package com.study.springboot.dao;

import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.Set;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 19:59
 */
@Repository
public interface PermissionsDao {

    /**
     * 通过用户名查询 权限
     * @param username 用户名
     * @return 权限
     */
    @Select("select permission_code from permissions where permission_id in (" +
            "select pid from role_permissions where rid in (" +
            "select rid from user_role where uid in (" +
            "select id from users where username = #{username})))")
    Set<String> queryPermissionsByUsername(String username);
}
