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
   


	

	