package com.kdemo.facebook.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
//@EnableOAuth2Sso
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception 
	{
		http
			.antMatcher("/**")
			.authorizeRequests()
			.antMatchers("/", "/login**", "/v2/**", "/swagger-resources", "/configuration/**")
			.permitAll()
			.anyRequest()
			.authenticated();
	}
}
