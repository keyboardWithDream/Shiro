package com.study.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;

import java.util.Scanner;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 13:59
 */
public class StartShiro {

    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);
        System.out.println("请输入账号:");
        String username = scan.nextLine();
        System.out.println("请输入密码:");
        String password = scan.nextLine();
        //创建SecurityManager
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        //创建Realm
        IniRealm realm = new IniRealm("classpath:shiro.ini");
        //设置Realm给安全管理器
        securityManager.setRealm(realm);
        //将SecurityUtils和SecurityManager进行绑定
        SecurityUtils.setSecurityManager(securityManager);
        //通过SecurityUtils获取主体
        Subject subject = SecurityUtils.getSubject();

        //[认证流程]
        //将认证账号和密码封装到token对象中
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        //如果认证失败则抛出IncorrectCredentialsException | 用户不存在抛出 UnknownAccountException
        boolean flag = false;
        try{
            //通过subject对象调用login进行认证
            subject.login(token);
            flag = true;
        }catch (IncorrectCredentialsException e) {
            System.out.println("认证失败!");
        }catch (UnknownAccountException e){
            System.out.println("用户不存在!");
        }
        System.out.println(flag ? "登录成功!":"登录失败!");

        //[授权流程]
        //判断是否有某个角色
        System.out.println(subject.hasRole("seller"));
        //判断是否有某个权限
        System.out.println(subject.isPermitted("order-add"));
    }
}
