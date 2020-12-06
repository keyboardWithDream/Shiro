# Shiro

## 简介

> ​	Apache Shiro 是 Java 的一个安全(权限)框架, Shiro 可以非常容易的开发出足够好的应用, 其不仅可以用在 JavaSE 环境, 也可以用在 JavaEE 环境. Shiro 可以完成: 认证 | 授权 | 加密 | 会话管理 | 与Web集成 | 缓存 | 等, [官方网址](http://shiro.apache.org).

![img](https://atts.w3cschool.cn/attachments/image/wk/shiro/1.png)

**Authentication**：身份认证 / 登录，验证用户是不是拥有相应的身份；

**Authorization**：授权，即权限验证，验证某个已认证的用户是否拥有某个权限；即判断用户是否能做事情，常见的如：验证某个用户是否拥有某个角色。或者细粒度的验证某个用户对某个资源是否具有某个权限；

**Session** **Management**：会话管理，即用户登录后就是一次会话，在没有退出之前，它的所有信息都在会话中；会话可以是普通 JavaSE 环境的，也可以是如 Web 环境的；

**Cryptography**：加密，保护数据的安全性，如密码加密存储到数据库，而不是明文存储；

**Web Support**：Web 支持，可以非常容易的集成到 Web 环境；

**Caching**：缓存，比如用户登录后，其用户信息、拥有的角色 / 权限不必每次去查，这样可以提高效率；

**Concurrency**：shiro 支持多线程应用的并发验证，即如在一个线程中开启另一个线程，能把权限自动传播过去；

**Testing**：提供测试支持；

**Run As**：允许一个用户假装为另一个用户（如果他们允许）的身份进行访问；

**Remember Me**：记住我，这个是非常常见的功能，即一次登录后，下次再来的话不用登录了。

**记住一点，Shiro 不会去维护用户、维护权限；这些需要我们自己去设计 / 提供；然后通过相应的接口注入给 Shiro 即可。**

---

![img](https://atts.w3cschool.cn/attachments/image/wk/shiro/2.png)

**Subject**：主体，代表了当前 “用户”，这个用户不一定是一个具体的人，与当前应用交互的任何东西都是 Subject，如网络爬虫，机器人等；即一个抽象概念；所有 Subject 都绑定到 SecurityManager，与 Subject 的所有交互都会委托给 SecurityManager；可以把 Subject 认为是一个门面；SecurityManager 才是实际的执行者；

**SecurityManager**：安全管理器；即所有与安全有关的操作都会与 SecurityManager 交互；且它管理着所有 Subject；可以看出它是 Shiro 的核心，它负责与后边介绍的其他组件进行交互，如果学习过 SpringMVC，你可以把它看成 DispatcherServlet 前端控制器；

**Realm**：域，Shiro 从从 Realm 获取安全数据（如用户、角色、权限），就是说 SecurityManager 要验证用户身份，那么它需要从 Realm 获取相应的用户进行比较以确定用户身份是否合法；也需要从 Realm 得到用户相应的角色 / 权限进行验证用户是否能进行操作；可以把 Realm 看成 DataSource，即安全数据源。

---

![img](https://atts.w3cschool.cn/attachments/image/wk/shiro/3.png)

**Subject**：主体，可以看到主体可以是任何可以与应用交互的 “用户”；

**SecurityManager**：相当于 SpringMVC 中的 DispatcherServlet 或者 Struts2 中的 FilterDispatcher；是 Shiro 的心脏；所有具体的交互都通过 SecurityManager 进行控制；它管理着所有 Subject、且负责进行认证和授权、及会话、缓存的管理。

**Authenticator**：认证器，负责主体认证的，这是一个扩展点，如果用户觉得 Shiro 默认的不好，可以自定义实现；其需要认证策略（Authentication Strategy），即什么情况下算用户认证通过了；

**Authrizer**：授权器，或者访问控制器，用来决定主体是否有权限进行相应的操作；即控制着用户能访问应用中的哪些功能；

**Realm**：可以有 1 个或多个 Realm，可以认为是安全实体数据源，即用于获取安全实体的；可以是 JDBC 实现，也可以是 LDAP 实现，或者内存实现等等；由用户提供；注意：Shiro 不知道你的用户 / 权限存储在哪及以何种格式存储；所以我们一般在应用中都需要实现自己的 Realm；

**SessionManager**：如果写过 Servlet 就应该知道 Session 的概念，Session 呢需要有人去管理它的生命周期，这个组件就是 SessionManager；而 Shiro 并不仅仅可以用在 Web 环境，也可以用在如普通的 JavaSE 环境、EJB 等环境；所以呢，Shiro 就抽象了一个自己的 Session 来管理主体与应用之间交互的数据；这样的话，比如我们在 Web 环境用，刚开始是一台 Web 服务器；接着又上了台 EJB 服务器；这时想把两台服务器的会话数据放到一个地方，这个时候就可以实现自己的分布式会话（如把数据放到 Memcached 服务器）；

**SessionDAO**：DAO 大家都用过，数据访问对象，用于会话的 CRUD，比如我们想把 Session 保存到数据库，那么可以实现自己的 SessionDAO，通过如 JDBC 写到数据库；比如想把 Session 放到 Memcached 中，可以实现自己的 Memcached SessionDAO；另外 SessionDAO 中可以使用 Cache 进行缓存，以提高性能；

**CacheManager**：缓存控制器，来管理如用户、角色、权限等的缓存的；因为这些数据基本上很少去改变，放到缓存中后可以提高访问的性能

**Cryptography**：密码模块，Shiro 提高了一些常见的加密组件用于如密码加密 / 解密的。

---

## 基于JavaSE应用

### 项目环境

#### 创建Maven项目

#### 导入Shiro依赖坐标

```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.7.0</version>
</dependency>
```

#### 创建Shiro配置文件

在`resource`目录下创建`shiro.ini`配置文件, 并写入用户| 角色|权限的配置

```ini
[users]
harlan=123456,seller
jack=666666,manager
admin=111111,admin
[roles]
admin=*
seller=order-add,order-del,order-list
manager=ck-add,ck-del,ck-list
```

---

### 基本使用

```java
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
```

### 流程分析

![流程](https://study-1259382847.cos.ap-chongqing.myqcloud.com/picbed/20201205150536.png)

1. 通过`subject.login(token)`进行登录, 就会将`token`包含的用户信息(账号&密码)传递给`SecurityManager`
2. `SecurityManager`就会调用`Anthenticator`进行身份认证
3. `Anthenticator`把`token`传递给对应的`Realm`
4. `Realm`根据得到的`token`调用`doGetAuthenticationInfo()`方法进行认证==(认证失败则抛出异常)==
5. 将校验的结果逐层返回到`sbject`, 如果`subject.login()`调用抛出异常, 则表示认证失败

---

## SpringBoot整合Shiro

### 项目环境

#### 导入Shiro依赖坐标

```xml
<!-- shiro -->
<dependency>
	<groupId>org.apache.shiro</groupId>
	<artifactId>shiro-spring</artifactId>
	<version>1.7.0</version>
</dependency>
```

#### `JdbcReaml`表结构规范

##### 用户信息表 users

```sql
create table users(
	id int primary key auto_increment,
    username varchar(32) not null,
    password varchar(32) not null
);
```

##### 角色信息表 user_roles

```sql
create table user_roles(
	id int primary key auto_increment,
    username varchar(32) not null,
    role_name varchar(32) not null
);
```

##### 权限信息表 roles_permissions

```sql
create table roles_permissions(
	id int primary key auto_increment,
    role_name varchar(32) not null,
    permission varchar(32) not null
);
```

#### Shiro配置类

需要`Realm`(数据获取) | `DefaultwebSecurityManager`(安全管理) | `ShiroFilterctoryBean`(过滤器)

```java
@Configuration
public class ShiroConfig {

    @Bean
    public Realm realm(DataSource dataSource) {
        JdbcRealm jdbcRealm = new JdbcRealm();
        //配置数据源
        jdbcRealm.setDataSource(dataSource);
        //开启授权功能
        jdbcRealm.setPermissionsLookupEnabled(true);
        return jdbcRealm;
    }

    @Bean
    public DefaultWebSecurityManager securityManager(Realm realm) {
        //SecurityManager需要Realm
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm);
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
        Map<String, String> filterMap = new HashMap<>();
        filterMap.put("/", "anon");
        filterMap.put("/login.html", "anon");
        filterMap.put("/user/login", "anon");
        filterMap.put("/static/**", "anon");
        filterMap.put("/**", "authc");
        filter.setFilterChainDefinitionMap(filterMap);
        //设置登录页面 | 未授权页面
        filter.setLoginUrl("/");
        filter.setUnauthorizedUrl("/");
        return filter;
    }
}
```

#### Service

```java
@Service
public class UserServiceImpl {

    public void checkLogin(String username, String password) {
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        subject.login(token);
    }
}
```

#### Controller

```java
@Controller
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserServiceImpl service;

    @RequestMapping("/login")
    public String login(String username, String password) {
        try {
            service.checkLogin(username, password);
            System.out.println("登录成功!");
            return "index";
        } catch (Exception e) {
            System.out.println("登录失败!");
            return "login";
        }
    }
}
```

#### 标签使用

> 当用户认证进入到主页面后, 需要显示用户信息及当前权限信息; Shiro提供了一套标签在页面来进行权限数据的展示.

Shiro提供了可供JSP使用和Thymeleaf的标签

* JSP中引用: 

  ```jsp
  <% taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
  ```

* Thymeleaf中引用:

  在`pom.xml`中导入thymeleaf模板对shiro标签支持的依赖

  ```xml
  <dependency> 
  	<groupId>com.github.theborakompanioni</groupId>
  	<artifactId>thymeleaf-extras-shiro</artifactId>
  	<version>2.0.0</version>
  </dependency>
  ```

  在``ShiroConfig`中配置

  ```java
  @Configuration
  public class ShiroConfig {
  
      @Bean
      public ShiroDialect shiroDialect() {
          return new ShiroDialect();
      }
      ...
  }
  ```

  导入标签库

  ```html
  <html xmlns:th="http://www.thymeleaf.org"
        xmlns:shiro="http://www.pollix.at/thymeleaf/shiro">
  </html>
  ```

---

## 自定义Realm

需要继承`AuthorizingRealm`, 重写`doGetAuthorizationInfo()`(获取授权数据) | `doGetAuthenticationInfo()`(获取认证数据) | `getName()`(自定义Realm名称)

```java
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
        System.out.println("正在授权...");
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
        System.out.println("正在认证...");
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
        return new SimpleAuthenticationInfo(username, user.getPassword(), getName());
    }
}
```

---

## 加盐加密

> 加密: 对原有的内容进行对应的编码, 得到不同内容但能够表示原始内容的数据.
>
> 加密规则可以自定义, 在项目中通常使用`BASE64`和`MD5`编码方式
>
> * BASE64: 可反编码的编码方式
> * MD5: 不可逆的编码方式
>
> Shiro提供了加密模块, 对输入的密码进行加密后再进行验证

```java
@Configuration
public class ShiroConfig {

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
    public Realm realm(HashedCredentialsMatcher matcher) {
        AccountRealm realm = new AccountRealm();
        //设置加密
        realm.setCredentialsMatcher(matcher);
        return realm;
    }
    
    ...
}
```

在自定义中的`Realm`中认证时也需要将盐信息传入

```java
@Override
protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
    System.out.println("正在认证...");
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
			//盐信息
            ByteSource.Util.bytes(user.getSalt()),
            getName());
}
```

保存到数据库时也需要加密

```java
public void register(String username, String password) {
    //加盐加密
    String salt = String.valueOf(new Random().nextInt(90000) + 10000);
    Md5Hash md5Hash = new Md5Hash(password, salt, 1);
    userDao.saveUser(username, md5Hash.toString(), salt);
}
```

---

## 退出

在Shiro过滤器中进行配置`logout`对应的路径

```java
filterMap.put("/logout", "logout");
```

并在页面的退出按钮上, 跳转到`logout`对应的路径

```html
<a href="/logout">退出</a>
```

---

## 授权

> 用户认证成功之后, 要进行相应的操作就需要有对应的权限; 在进行操作之前对权限进行检查
>
> 权限控制通常有两类做法:
>
> * 不同身份的用户登录, 使用不同的操作菜单
> * 对所有用户显示所有菜单, 当用户点击菜单以后再进行验证权限

![常见过滤器](https://img-blog.csdnimg.cn/202009091824317.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MTk2ODUyNA==,size_16,color_FFFFFF,t_70#pic_center)

### HTML 授权

在菜单页面只显示当前用户拥有权限的, 即使用==Shiro标签==

```html
<shiro:hasPermission name="roleName"> ... </shiro:hasPermission>
```

### 过滤器授权

在过滤器映射中设置接口访问需要的==权限==

```java
filterMap.put("/user/del", "perms[sys:delete]");
```

权限不足时可自定义跳转

```java
filter.setUnauthorizedUrl("/lessPermission.html");
```

### 注解授权

配置Spring对Shiro注解的支持, 在ShiroConfig中配置

```java
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
```

在Controller中使用`@RequiresPermissions()`(对应权限) 或 `@RequiresRoles()`(对应角色) 注解.

```java
@RequiresRoles("admin")
@PostMapping("/del")
public String delUser(String username) {
    service.deleteUserByUsername(username);
    return "index";
}
```

| 注解                                                         | 作用                                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `@RequiresAuthentication`                                    | 表示当前`Subject`已经通过login 进行了身份验证；即``Subject`. `isAuthenticated()`返回true。 |
| `@RequiresUser`                                              | 表示当前`Subject`已经身份验证或者通过记住我登录的。          |
| `@RequiresGuest`                                             | 表示当前`Subject`没有身份验证或通过记住我登录过，即是游客身份。 |
| `@RequiresRoles(value={“admin”, “user”}, logical= Logical.AND)` |`@RequiresRoles(value={“admin”})` |`@RequiresRoles({“admin“})` | 表示当前`Subject`需要角色`admin`和`user`。                   |
| `@RequiresPermissions (value={“user:a”, “user:b”}, logical= Logical.OR)` | 表示当前`Subject`需要权限`user:a`或`user:b`。                |

==注意:使用注解时, 当权限不足会抛出`AuthorizationException`, 并自动返回异常页面==![](https://study-1259382847.cos.ap-chongqing.myqcloud.com/picbed/20201206121700.png)

==可以通过全局异常处理进行跳转==

```java
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
```

### 手动授权

在Controller | Service 中使用通过获取`Sbuject`自己编写逻辑判断处理.

```java
Subject subject  = SecurityUtils.getSubject();
if (subject.isPermitted("sys:delete")) {
    return "index";
}else {
    return "lessPermission";
}
```

---

## 缓存使用

> ​	使用Shiro进行权限管理过程中, 每次授权都会访问`realm`中的`doGetAuthorizationInfo()`方法查询当前角色及权限信息, 如果系统的用户量比较大则会导致数据库造成比较大的压力.
>
> Shiro支持缓存以降低数据库的访问压力==(缓存授权信息)==

### 第三方缓存

查看此博文使用redis[网址](https://blog.csdn.net/u010514380/article/details/82185451)

---

## Session管理

> Shiro进行认证和授权是基于session实现的, Shiro包含了对session的管理

### 自定义Seesion管理

1. 自定义session管理器
2. 将自定义session管理器给`SecurityManager`

```java
@Bean
public DefaultSessionManager sessionManager() {
    DefaultSessionManager sessionManager = new DefaultSessionManager();
    //设置session过期时间等...
    sessionManager.setGlobalSessionTimeout(15 * 1000);
    return sessionManager;
}

@Bean
public DefaultWebSecurityManager securityManager(Realm realm, DefaultSessionManager sessionManager) {
	DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
	//SecurityManager需要Realm
	securityManager.setRealm(realm);
	//配置session管理器
	securityManager.setSessionManager(sessionManager);
	return securityManager;
}
```

---

## RememberMe

> 将用户对页面访问的权限分为三个级别
>
> * 未认证可访问的页面
> * 曾认证可访问的页面
> * 已认证可访问的页面

1. 在过滤器中设置 或 使用注解 添加对应记住我可访问的`url`

```java
filterMap.put("/index.html", "user");
```

```java
@RequiresUser
@RequestMapping("/index.html")
public String index() {
    return "index";
}
```

2. 在`ShiroConfig`中配置基于`cookie`的rememberMe管理器

```java
@Bean
public CookieRememberMeManager cookieRememberMeManager() {
    CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
    SimpleCookie cookie = new SimpleCookie();
    cookie.setMaxAge(30 * 24 * 60 * 60);
    rememberMeManager.setCookie(cookie);
    return rememberMeManager;
}
```

```java
@Bean
public DefaultWebSecurityManager securityManager(Realm realm, DefaultSessionManager sessionManager, CookieRememberMeManager rememberMeManager) {
    DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
    //SecurityManager需要Realm
    securityManager.setRealm(realm);
    //配置session管理器
    securityManager.setSessionManager(sessionManager);
    //配置rememberMe管理器
    securityManager.setRememberMeManager(rememberMeManager);
    return securityManager;
}
```

3. 在Controller中需要获取Remember是否选择(boonlean值)传入Service, 在Service中进行设置

   ```java
   public void checkLogin(String username, String password, boolean rememberMe) {
       Subject subject = SecurityUtils.getSubject();
       UsernamePasswordToken token = new UsernamePasswordToken(username, password);
       //设置rememberMe
       token.setRememberMe(rememberMe);
       subject.login(token);
   }
   ```

