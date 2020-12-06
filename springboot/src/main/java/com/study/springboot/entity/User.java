package com.study.springboot.entity;

import lombok.Data;

import java.io.Serializable;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 19:32
 */
@Data
public class User implements Serializable {

    private Integer id;
    private String username;
    private String password;
    private String salt;
}
