# Spring Security

## 前言
  
   很久之间就像系统的学习一个框架，但是很多时候都是要用的时候才临时磨枪，了解得一知半解，对着网上的代码一顿胡抄，现在开始希望养成一种善于记学习笔记的习惯，既能督促自己的学习，也能有个回顾的文本

## 概述
   
   Spring Security主要分为两个部分，认证(Authentication) who are you?和授权(Authoriztion) what you can do？ Spring Security对此都有类似的架构和设计来方便扩展和替换安全策略。
   
## Authentication 认证
### AuthenticationManager
   `AuthenticationManager`是authentication的主要接口，其中只有一个方法。该类位于`org.springframework.security.authentication`包中
	 
	public interface AuthenticationManger {
		Authentication authenticate(Authentication authentication) throw AuthenticationException
	}

   注释注：该方法尝试认证一个传入的`Authentication`对象，并返回一个经过充分鉴定的`Authentication`对象(包含`authorities`和`credentials`)
   `authenticate()`方法一般有3种结果：
   
1. 返回一个`Authentication`(通常`authenticated=true`)，告诉输入是一个经过验证有效的`principal`
2. 抛出`AuthenticationException`,告诉输入是一个非法的`principal`
3. 返回`null`，当它无法判定时 

### Authentication
   注释注：它代表一个认证的请求或者一个已经认证过的`principal`,认证的过程一般在`AuthenticationManager.authenticate(Authencation)`中进行。一旦认证请求通过了就会被存储到`thread-local`中，存储对象为`SecurityContext`，由`SecurityContextHolder`进行管理，这里面用到了策略设计模式，在下面会进行解析。如果`Authentication`中的`authenticated`没有被设为`true`,它会被框架中的执行它的任何`security interceptor`进行认证。该类位于`org.springframework.security.core`包中
	
	public interface Authentication extends Principal, Serializable {
		//在认证过程中由AuthenticationManager注入该principal所授予的权限(authorities)
		Collection<? extends GrantedAuthority> getAuthorities();
       //一般用来证明该principal是合法，大多数情况是密码，但是也可能是其他的认证证书 
		Object getCredentials();
		//认证请求的一些额外信息，例如IP地址之类的
		Object getDetails();
		//被认证principal的身份，如果是账号密码认证，这通常是账号。大多数情况下，AuthenticationManager在认证后会注入更为丰富的身份信息，所以Pincipal一般会被authentication providers进行扩展
		Object getPrincipal();
		//指出该Authentication是否应该提交到AuthenticationManager中进行认证。一般来说，AuthenticationManager会在认证成功之后返回一个不可改变的Authentication, 该方法会返回true，然后其他的安全拦截器将不会请求AuthenticationManager进行认证，这将提升性能
		boolean isAuthenticated();

		void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
	}

### SecurityContext
   其实就是用来在`thread-local`中保存`Authentication`的，与当前执行的线程绑定
	
	public interface SecurityContext extends Serializable {
		Authentication getAuthentication();
		void setAuthentication(Authentication authentication);
	}
  
   有一个默认实现`SecurityContextImpl`，都位于`org.springframework.security.core.context`包中
   
### SecurityContextHolder
   用来给当前执行的线程提供`SecurityContext`, 这里面是一个策略模式来指派不同的`SecurityContextHolderStrategy`将`SecurityContext`与当前的线程进行绑定，主要是考虑JVM的差异，通过`strategyName`来指定不同的`SecurityContextHolderStrategy`，默认为`MODE_THREADLOCAL`。该类位于`org.springframework.security.core.context`包中
   指定`SecurityContextHolder`中的策略
   
	private static void initialize() {
		if (!StringUtils.hasText(strategyName)) {
			// Set default
			strategyName = MODE_THREADLOCAL;
		}

		if (strategyName.equals(MODE_THREADLOCAL)) {
			strategy = new ThreadLocalSecurityContextHolderStrategy();
		}
		else if (strategyName.equals(MODE_INHERITABLETHREADLOCAL)) {
			strategy = new InheritableThreadLocalSecurityContextHolderStrategy();
		}
		else if (strategyName.equals(MODE_GLOBAL)) {
			strategy = new GlobalSecurityContextHolderStrategy();
		}
		else {
			// Try to load a custom strategy
			try {
				Class<?> clazz = Class.forName(strategyName);
				Constructor<?> customStrategy = clazz.getConstructor();
				strategy = (SecurityContextHolderStrategy) customStrategy.newInstance();
			}
			catch (Exception ex) {
				ReflectionUtils.handleReflectionException(ex);
			}
		}

		initializeCount++;
	}
	
   设置`strategyName`会触发策略的替换
   
	public static void setStrategyName(String strategyName) {
		SecurityContextHolder.strategyName = strategyName;
		initialize();
	}
	

### SecutityContextHolderStrategy
   用于保存安全上下文`SecurityContext`的策略，与线程`thread`相关，该类位于`org.springframework.security.core.context`包中

	public interface SecurityContextHolderStrategy {
		void clearContext();
		SecurityContext getContext();
		void setContext(SecurityContext context);
		SecurityContext createEmptyContext();
	}

#### ThreadLocalSecurityHolderStrategy
   `ThreadLocalSecurityHolderStrategy`是`SecutityContextHolderStrategy`的默认实现，主要通过`ThreadLocal`将`SecurityContext`与线程进行绑定，其他实现还有`GlobalSecurityContextHolderStrategy`和`InheritableThreadLocalSecurityHolderStrategy`该类位于`org.springframework.security.core.context`包中

	final class ThreadLocalSecurityContextHolderStrategy implements
	
		private static final ThreadLocal<SecurityContext> contextHolder = new ThreadLocal<SecurityContext>();

		public void clearContext() {
			contextHolder.remove();
		}

		public SecurityContext getContext() {
			SecurityContext ctx = contextHolder.get();

			if (ctx == null) {
				ctx = createEmptyContext();
				contextHolder.set(ctx);
			}

			return ctx;
		}

		public void setContext(SecurityContext context) {
			Assert.notNull(context, "Only non-null SecurityContext instances are permitted");
			contextHolder.set(context);
		}

		public SecurityContext createEmptyContext() {
			return new SecurityContextImpl();
		}
	}
 
   下面附上一张类图方便理解
   
   ![](https://raw.githubusercontent.com/CANGWU/pic/master/book/spring-security/SecurityContext.png)


### ProviderManager
`ProviderManager`是AuthenticationManager的默认实现，这里有一个委托者模式的实现，它持有按照顺序排列的一个List的`AuthenticationProvider`。在`ProviderManager.authenticate(Authentication)`方法中通过循环的方式调用`AuthenticationProvider.authenticate(Authentication)`对传递的`Authentication`进行尝试认证，当List中有一个`AuthenticationProvider`对`Authentication`的认证返回一个非空的`AuthenticationProvider`并且无异常抛出，说明该`AuthenticationProvider`有能力对传递的`Authentication`进行认证并且认证成功，调用链下游的`AuthenticationProvider`将不需要继续尝试。同时在尝试认证的过程中会对上次认证产生的`AuthenticationException`进行保存，当没有`AuthenticationProvider`返回非空的`Authentication`,最后一次遗留的`AuthencationException`将会被使用。如果List中的`AuthenticationProvider`都不能对`Authentication`进行认证，那么`parent`(`AuthenticationManager`)(当`parent非空时`)将尝试进行认证。当然如果`parent`都无法返回非空的`Authentication`，那么一个`ProviderNotFoundException`将会被抛出。在获取到有效的认证结果`Authentication`, 一个必要的清理工作需要进行，例如清理`Authentication`中的`Credentials`(密码)。这个过程中还有认证成功或者认证失败的事件广播，但是默认的实现是空的，该类位于`org.springframework.security.authentication`包中
`ProviderManager`中的关键的引用对象。	

	//认证事件广播，默认实现为空
	private AuthenticationEventPublisher eventPublisher = new NullEventPublisher();
	//认证AuthenticationProvider列表，认证的主要提供者
	private List<AuthenticationProvider> providers = Collections.emptyList();
	//父级AuthenticationManager，在AuthenticationProvider列表尝试认证失败后调用
	private AuthenticationManager parent;
	
`ProviderManager.authenticate(Authentication)`方法
	
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Class<? extends Authentication> toTest = authentication.getClass();
		AuthenticationException lastException = null;
		Authentication result = null;
		boolean debug = logger.isDebugEnabled();

		//循环调用AuthenticationProvider尝试对Authentication进行认证
		for (AuthenticationProvider provider : getProviders()) {
			//检查AuthenticationProvider是否支持对该类Authentication进行认证，
			//如果不支持，则进入下一个循环
			if (!provider.supports(toTest)) {
				continue;
			}

			if (debug) {
				logger.debug("Authentication attempt using "
						+ provider.getClass().getName());
			}

			//注意在循环调用的过程中，如果没有认证成功，只有最后一次的捕捉的异常有效
			try {
				result = provider.authenticate(authentication);

				if (result != null) {
					copyDetails(authentication, result);
					break;
				}
			}
			catch (AccountStatusException e) {
				prepareException(e, authentication);
				// SEC-546: Avoid polling additional providers if auth failure is due to
			   // invalid account status
				throw e;
			}
			catch (InternalAuthenticationServiceException e) {
				prepareException(e, authentication);
				throw e;
			}
			catch (AuthenticationException e) {
				lastException = e;
			}
		}

		//在AuthenticationProvider列表尝试认证失败后尝试调用parent进行认证
		if (result == null && parent != null) {
			// Allow the parent to try.
			try {
				result = parent.authenticate(authentication);
			}
			catch (ProviderNotFoundException e) {
			// ignore as we will throw below if no other exception occurred prior to
			// calling parent and the parent
			// may throw ProviderNotFound even though a provider in the child already
			// handled the request
			}
			catch (AuthenticationException e) {
				lastException = e;
			}
		}
		//认证成功后的清理操作或者其他操作
		if (result != null) {
			if (eraseCredentialsAfterAuthentication
					&& (result instanceof CredentialsContainer)) {
				// Authentication is complete. Remove credentials and other secret data
				// from authentication
				((CredentialsContainer) result).eraseCredentials();
			}
			//认证成功的事件广播
			eventPublisher.publishAuthenticationSuccess(result);
			return result;
		}

		// Parent was null, or didn't authenticate (or throw an exception).
		//认证失败的抛出最后一次保留的异常
		if (lastException == null) {
			lastException = new ProviderNotFoundException(messages.getMessage(
					"ProviderManager.providerNotFound",
					new Object[] { toTest.getName() },
					"No AuthenticationProvider found for {0}"));
		}
       //这里的方法进行了认证失败的广播
		prepareException(lastException, authentication);

		throw lastException;
	}
		
	private void prepareException(AuthenticationException ex, Authentication auth) {
		eventPublisher.publishAuthenticationFailure(ex, auth);
	}
	
### AuthenticationProvider
   `AuthenticationProvider`是真正进行认证的工作的接口类，通过注入不同的排列组合的`AuthenticationProvider`实现，使得`ProviderManager`可以针对不同的请求进行高配置化的认证。
   
	public interface AuthenticationProvider {
	   //执行认证的具体方法
	   //通常会返回一个带有credentials的被认证的Authentication
	   //也可能返回null，当不支持认证传递过来的Authentication，然后下一个AuthenticationProvider会在ProviderManager被调用
	   //认证失败会抛出AuthenticationException
		Authentication authenticate(Authentication authentication) throws AuthenticationException;
		//返回该AuthenticationProvider是否支持认证该Authentication类型
		//然而返回true也不能保证一定能进行认证，authenticate方法依然有可能会返回null
		boolean supports(Class<?> authentication);
}

#### AbstractUserDetailsAuthenticationProvider
`AbstractUserDetailsAuthenticationProvider`是一个抽象类，继承了`AuthenticationProvider`，作为一个与`UserDetails`工作的基类。这个类被设计用来返回`UsernamePasswordAuthenticationToken`(`Authentication`的一个子类)，往下一点会介绍一下`UserDetails`和`Authentication`区别，这里可以简单认为`UserDetails`是提供系统内部持有的真正正确的用户信息的接口，`Authentication`是提供外来认证信息以及经认证后填充(来自`UserDetail`)的用户信息。该类位于`org.springframework.security.authentication.dao`包中
`AbstractUserDetailsAuthenticationProvider`关键对象引用

	//用户信息缓存，默认实现为null，因为通常在一个Web应用中，SecurityContext一般会保存在用户的session中
	//并且当Authentication.isAuthenticated为true并不需要在每次的请求都要重新认证
	private UserCache userCache = new NullUserCache();
	//认证前置处理
	private UserDetailsChecker preAuthenticationChecks = new DefaultPreAuthenticationChecks();
	//认证后置处理
	private UserDetailsChecker postAuthenticationChecks = new DefaultPostAuthenticationChecks();
	//权限匹配注入了，用于认证成功后为UsernamePasswordAuthenticationToken注入对应的GrantedAuthority
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
	
	
`AbstractUserDetailsAuthenticationProvider.authenticate(Authentication)`方法
	
	public Authentication authenticate(Authentication authentication)throws AuthenticationException {
	   //支持UsernamePasswordAuthenticationToken的认证
		Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
				messages.getMessage(
						"AbstractUserDetailsAuthenticationProvider.onlySupports",
						"Only UsernamePasswordAuthenticationToken is supported"));

		// Determine username
		String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED"
				: authentication.getName();
				
       //尝试从缓存中获取用户信息
		boolean cacheWasUsed = true;
		UserDetails user = this.userCache.getUserFromCache(username);

		if (user == null) {
			cacheWasUsed = false;

			try {
			   //缓存中没有用户时，尝试从用户信息的来源获取，一般是数据库
				user = retrieveUser(username,
						(UsernamePasswordAuthenticationToken) authentication);
			}
			catch (UsernameNotFoundException notFound) {
				logger.debug("User '" + username + "' not found");

				if (hideUserNotFoundExceptions) {
					throw new BadCredentialsException(messages.getMessage(
							"AbstractUserDetailsAuthenticationProvider.badCredentials",
							"Bad credentials"));
				}
				else {
					throw notFound;
				}
			}
          //认证后返回的user为null，说明用户不存在，认证失败
			Assert.notNull(user,
					"retrieveUser returned null - a violation of the interface contract");
		}

		try {
		   //认证前置处理
			preAuthenticationChecks.check(user);
			//该方法为抽象方法，可以在子类中添加自定义的认证处理工作，一般是对比密码之类的
			additionalAuthenticationChecks(user,
					(UsernamePasswordAuthenticationToken) authentication);
		}
		catch (AuthenticationException exception) {
			if (cacheWasUsed) {
				// There was a problem, so try again after checking
				// we're using latest data (i.e. not from the cache)
				cacheWasUsed = false;
				user = retrieveUser(username,
						(UsernamePasswordAuthenticationToken) authentication);
				preAuthenticationChecks.check(user);
				additionalAuthenticationChecks(user,
						(UsernamePasswordAuthenticationToken) authentication);
			}
			else {
				throw exception;
			}
		}

       //认证后置处理
		postAuthenticationChecks.check(user);
       //如果缓存中没有该UserDetails，将其放进缓存
		if (!cacheWasUsed) {
			this.userCache.putUserInCache(user);
		}

		Object principalToReturn = user;

		if (forcePrincipalAsString) {
			principalToReturn = user.getUsername();
		}
       //返回认证成功的UsernamePasswordAuthenticationToken
		return createSuccessAuthentication(principalToReturn, authentication, user);
	}
	
	protected Authentication createSuccessAuthentication(Object principal,
			Authentication authentication, UserDetails user) {
	   //返回一些必要的信息，并且设置isAuthenticated为true
		UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
				principal, authentication.getCredentials(),
				authoritiesMapper.mapAuthorities(user.getAuthorities()));
		result.setDetails(authentication.getDetails());

		return result;
	}
`UsernamePasswordAuthenticationToken`中只在`AuthenticationManager`或者`AuthenticationProvider`的子类中使用的用来生成可信赖的`Authentication`的构造器

	public UsernamePasswordAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		super.setAuthenticated(true); // must use super, as we override
	}
	

#### DaoAuthenticationProvider
`DaoAuthenticationProvider`是`AbstractUserDetailsAuthenticationProvider`的实现类，这是最常用的一个`AuthenticationProvider`，顾名思义，主要通过数据层进行用户信息认证的(一般是数据库)，这个类中主要关注`additionalAuthenticationChecks`和`retrieveUser`方法。该类位于`org.springframework.security.authentication.dao`
	
	public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
       //密码的编码器，其实类似于加盐转义之类的密码加密解密器
		private PasswordEncoder passwordEncoder;
		//用于实现获取UserDetails的具体类
		private UserDetailsService userDetailsService;

		public DaoAuthenticationProvider() {
			setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
		}

		protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
			if (authentication.getCredentials() == null) {
				logger.debug("Authentication failed: no credentials provided");

				throw new BadCredentialsException(messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.badCredentials",
					"Bad credentials"));
			}

			String presentedPassword = authentication.getCredentials().toString();
       	//对比UserDetails中的密码和Authentication中的密码的
       	//如果相同则认证成功，反之，认证失败，抛出认证证书错误的BadCredentialsException的异常
       	//一般是比较转义后的密码
			if (!passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
				logger.debug("Authentication failed: password does not match stored value");

				throw new BadCredentialsException(messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.badCredentials",
					"Bad credentials"));
			}
		}


		//这个方法其实就是通过UserDetailsService.loadUserByUsername(username)根据用户名获取用户信息
		//如果loadedUser不存在，抛出UsernameNotFoundException的异常
		//UserDetailsService需要具体的实现，一般都是查询数据库
		protected final UserDetails retrieveUser(String username,
				UsernamePasswordAuthenticationToken authentication)
				throws AuthenticationException {
			UserDetails loadedUser;

			try {
				loadedUser = this.getUserDetailsService().loadUserByUsername(username);
			}
			catch (UsernameNotFoundException notFound) {
				if (authentication.getCredentials() != null) {
					String presentedPassword = authentication.getCredentials().toString();
					passwordEncoder.matches(presentedPassword, userNotFoundEncodedPassword);
				}
				throw notFound;
			}
			catch (Exception repositoryProblem) {
				throw new InternalAuthenticationServiceException(
						repositoryProblem.getMessage(), repositoryProblem);
			}

			if (loadedUser == null) {
				throw new InternalAuthenticationServiceException(
						"UserDetailsService returned null, which is an interface contract violation");
			}
			return loadedUser;
		}
		
		.....

	}
	
`UserDetailsService`的接口需要由我们自主实现，然后注入到`DaoAuthenticationProvider`中使用


	public interface UserDetailsService {
	   //根据用户名获取用户信息
		UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
	}
	
`DaoAuthenticationProvider`的认证思路很简单，概括来说就是，用户提交用户名和密码，被封装成`UsernamePasswordAuthenticationToken`，`DaoAuthenticationProvider`在`retrieveUser`方法通过`UserDetailsService`根据用户名获取`UserDetails`，然后在`additionalAuthenticationChecks`方法中将`UserDetails`和`UsernamePasswordAuthenticationToken`的密码进行对比，然后返回结果
   下面附上一张类图方便理解
   
   ![](https://raw.githubusercontent.com/CANGWU/pic/master/book/spring-security/ProviderManager.png)
   
   附上一张官方给出的总体Authentication结构图
   
   ![](https://raw.githubusercontent.com/CANGWU/pic/master/book/spring-security/Authentication.png)







	

	