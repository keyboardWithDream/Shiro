package com.study.springboot.dao;

import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.Set;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 19:46
 */
@Repository
public interface RoleDao {

    /**
     * 通过用户名查询角色
     * @param username 用户名
     * @return 角色名
     */
    @Select("select role_name from roles where role_id in (" +
            "select rid from user_role where uid in (" +
            "select id from users where username = #{username}" +
            "))")
    Set<String> queryRoleNamesByUsername(String username);
}
