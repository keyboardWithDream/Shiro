package com.study.springboot.dao;

import com.study.springboot.entity.User;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 19:34
 */
@Repository
public interface UserDao {

    /**
     * 通过用户名查询用户
     * @param username 用户名
     * @return 用户信息
     */
    @Select("select * from users where username = #{username}")
    User queryUserByUsername(String username);

    /**
     * 保存用户
     * @param username 用户名
     * @param password 密码
     * @param salt 盐
     */
    @Insert("insert into users(username, password, salt) values (#{username}, #{password}, #{salt})")
    void saveUser(@Param("username") String username,@Param("password") String password, @Param("salt") String salt);

    /**
     * 通过用户名删除用户
     * @param username 用户名
     */
    @Delete("delete from users where username = #{username}")
    void deleteUserByUsername(String username);
}
