package com.study.springboot.shiro;

import com.study.springboot.dao.PermissionsDao;
import com.study.springboot.dao.RoleDao;
import com.study.springboot.dao.UserDao;
import com.study.springboot.entity.User;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import javax.annotation.Resource;
import java.util.Set;

/**
 * @author isharlan.hu@gmail.com
 * @date 2020/12/5 17:43
 */
public class AccountRealm extends AuthorizingRealm {

    @Resource
    private UserDao userDao;
    @Resource
    private RoleDao roleDao;
    @Resource
    private PermissionsDao permissionsDao;

    @Override
    public String getName() {
        return "AccountRealm";
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //获取当前用户的用户名
        String username = (String)principalCollection.iterator().next();
        //根据用户名查询当前用户的角色列表
        Set<String> roleName = roleDao.queryRoleNamesByUsername(username);
        //根据用户名查询当前用户的权限列表
        Set<String> permissions = permissionsDao.queryPermissionsByUsername(username);
        //将信息存入SimpleAuthorizationInfo并返回
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setRoles(roleName);
        info.setStringPermissions(permissions);
        return info;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        //重token中获取用户名
        String username = token.getUsername();
        //根据用户名,从数据库中查询当前用户
        User user = userDao.queryUserByUsername(username);
        //返回查询结果交给Shiro处理
        if (user == null){
            //返回空
            return null;
        }
        //返回SimpleAuthenticationInfo
        return new SimpleAuthenticationInfo(username,
                user.getPassword(),
                ByteSource.Util.bytes(user.getSalt()),
                getName());
    }
}
