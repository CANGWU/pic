# Spring Security

## 前言
  
   很久之间就像系统的学习一个框架，但是很多时候都是要用的时候才临时磨枪，了解得一知半解，对着网上的代码一顿胡抄，现在开始希望养成一种善于记学习笔记的习惯，既能督促自己的学习，也能有个回顾的文本

## 概述
   
   Spring Security主要分为两个部分，鉴定(Authentication) who are you?和授权(Authoriztion) what you can do？ Spring Security对此都有类似的架构和设计来方便扩展和替换安全策略。
   
## Authentication 鉴定
### AuthenticationManager
   `AuthenticationManager`是authentication的主要接口，其中只有一个方法。该类位于`org.springframework.security.authentication`包中
	 
	public interface AuthenticationManger{
		Authentication authenticate(Authentication authentication) throw AuthenticationException
	}

   注释注：该方法尝试鉴定一个传入的`Authentication`对象，并返回一个经过充分鉴定的`Authentication`对象(包含`authorities`和`credentials`)
   `authenticate()`方法一般有3种结果：
   
1. 返回一个`Authentication`(通常`authenticated=true`)，告诉输入是一个经过验证有效的`principal`
2. 抛出`AuthenticationException`,告诉输入是一个非法的`principal`
3. 返回`null`，当它无法判定时 

### Authentication





