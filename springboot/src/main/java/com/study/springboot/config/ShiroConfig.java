package com.study.springboot.config;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import com.study.springboot.shiro.AccountRealm;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * Shiro配置类
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 15:34
 */
@Configuration
public class ShiroConfig {

    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator autoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        autoProxyCreator.setProxyTargetClass(true);
        return autoProxyCreator;
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(DefaultWebSecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        //设置安全管理器
        advisor.setSecurityManager(securityManager);
        return advisor;
    }

    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        //指定加密规则
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        //加密方式
        matcher.setHashAlgorithmName("md5");
        //加密次数
        matcher.setHashIterations(1);
        return matcher;
    }

    @Bean
    public DefaultSessionManager sessionManager() {
        DefaultSessionManager sessionManager = new DefaultSessionManager();
        //设置session过期时间
        sessionManager.setGlobalSessionTimeout(15 * 1000);
        return sessionManager;
    }

    @Bean
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }

    @Bean
    public Realm realm(HashedCredentialsMatcher matcher) {
        AccountRealm realm = new AccountRealm();
        //设置加密
        realm.setCredentialsMatcher(matcher);
        return realm;
    }

    @Bean
    public CookieRememberMeManager cookieRememberMeManager() {
        CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
        SimpleCookie cookie = new SimpleCookie("RememberMe");
        cookie.setMaxAge(30 * 24 * 60 * 60);
        rememberMeManager.setCookie(cookie);
        return rememberMeManager;
    }

    @Bean
    public DefaultWebSecurityManager securityManager(Realm realm, DefaultSessionManager sessionManager, CookieRememberMeManager rememberMeManager) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        //SecurityManager需要Realm
        securityManager.setRealm(realm);
        //配置session管理器
        securityManager.setSessionManager(sessionManager);
        securityManager.setRememberMeManager(rememberMeManager);
        return securityManager;
    }


    @Bean
    public ShiroFilterFactoryBean shiroFilter(DefaultWebSecurityManager securityManager) {
        //过滤器是shiro权限校验的核心, 进行认证和授权是需要SecurityManager
        ShiroFilterFactoryBean filter = new ShiroFilterFactoryBean();
        filter.setSecurityManager(securityManager);
        //设置拦截规则
        // anon     表示匿名用户可访问
        // authc    表示认证用户可访问
        // user     使用RememberMe用户可访问
        // perms    对应权限可访问
        // role     对象角色可访问
        // logout   退出
        Map<String, String> filterMap = new HashMap<>(7);
        filterMap.put("/", "anon");
        filterMap.put("/login.html", "anon");
        filterMap.put("/user/login", "anon");
        filterMap.put("/index.html", "user");
        filterMap.put("/static/**", "anon");
        filterMap.put("/**", "authc");
        filterMap.put("/del.html", "perms[sys:delete]");
        //设置退出
        filterMap.put("/logout", "logout");
        filter.setFilterChainDefinitionMap(filterMap);
        //设置登录 | 未授权 跳转页面
        filter.setLoginUrl("/");
        filter.setUnauthorizedUrl("/lessPermission.html");
        return filter;
    }
}
