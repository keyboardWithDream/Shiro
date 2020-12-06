package com.study.springboot.utils;

import org.apache.shiro.authz.AuthorizationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 * 全局异常处理器
 * @author isharlan.hu@gmail.com
 * @date 2020/12/6 12:18
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler
    public String doException(Exception e) {
        if (e instanceof AuthorizationException){
            return "lessPermission";
        }
        return null;
    }
}
