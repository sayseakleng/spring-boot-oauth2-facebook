package com.kdemo.facebook.config;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.filter.CompositeFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

@Configuration
@EnableOAuth2Client
@EnableWebSecurity
public class FacebookSecurityConfiguration extends WebSecurityConfigurerAdapter {

	  @Autowired
	  private OAuth2ClientContext oauth2ClientContext;
	  
	  private TokenStore tokenStore = new InMemoryTokenStore();
	
	  
	  @Override
	  protected void configure(HttpSecurity http) throws Exception {
	    http
	      .antMatcher("/**")
	      .sessionManagement()
	      	.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	      .and()
	      .authorizeRequests()
	        .antMatchers("/", "/login**", "/webjars/**")
	        .permitAll()
	      .anyRequest()
	        .authenticated().and().logout().logoutSuccessUrl("/").permitAll()
	        .and().csrf().csrfTokenRepository(csrfTokenRepository())
	        .and().addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
	        .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
	  }
	  
	  private Filter ssoFilter() {
		  CompositeFilter filter = new CompositeFilter();
		  List<Filter> filters = new ArrayList<>();

		  OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
		  OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook(), oauth2ClientContext);
		  facebookFilter.setRestTemplate(facebookTemplate);
		  facebookFilter.setTokenServices(new UserInfoTokenServices(facebookResource().getUserInfoUri(), facebook().getClientId()));
		 
		  // customize to save facebook accessToken
		  facebookFilter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {
			
			@Override
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {
				
				if(authentication instanceof OAuth2Authentication) {
					OAuth2Authentication oAuth2Authentication = (OAuth2Authentication)authentication;
					String fbUserId = (String) oAuth2Authentication.getPrincipal();
					System.out.println(fbUserId);
					
					// to get user name
					//((OAuth2Authentication) authentication).getUserAuthentication()
					
					OAuth2AuthenticationDetails oAuth2AuthenticationDetails = (OAuth2AuthenticationDetails) authentication.getDetails();
					String tokenValue = oAuth2AuthenticationDetails.getTokenValue();
					OAuth2AccessToken token = new DefaultOAuth2AccessToken(tokenValue);
					tokenStore.storeAccessToken(token, oAuth2Authentication);
					response.getWriter().write(tokenValue);
				}
			}
		  });
		  
		  
		  
		  filters.add(facebookFilter);

		  OAuth2ClientAuthenticationProcessingFilter githubFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/github");
		  OAuth2RestTemplate githubTemplate = new OAuth2RestTemplate(github(), oauth2ClientContext);
		  githubFilter.setRestTemplate(githubTemplate);
		  githubFilter.setTokenServices(new UserInfoTokenServices(githubResource().getUserInfoUri(), github().getClientId()));
		  filters.add(githubFilter);

		  filter.setFilters(filters);
		  return filter;		
	 }
	  
	  
	  
	  private Filter csrfHeaderFilter() {
		  return new OncePerRequestFilter() {
		    @Override
		    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		        FilterChain filterChain) throws ServletException, IOException {
		      CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		      if (csrf != null) {
		        Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
		        String token = csrf.getToken();
		        if (cookie == null || token != null && !token.equals(cookie.getValue())) {
		          cookie = new Cookie("XSRF-TOKEN", token);
		          cookie.setPath("/");
		          response.addCookie(cookie);
		        }
		      }
		      filterChain.doFilter(request, response);
		    }
		  };
		}
	  
	  @Bean
	  @ConfigurationProperties("facebook.client")
	  OAuth2ProtectedResourceDetails facebook() {
	    return new AuthorizationCodeResourceDetails();
	  }
	  
	  @Bean
	  @ConfigurationProperties("facebook.resource")
	  ResourceServerProperties facebookResource() {
	    return new ResourceServerProperties();
	  }
	  
	  @Bean
	  @ConfigurationProperties("github.client")
	  OAuth2ProtectedResourceDetails github() {
	  	return new AuthorizationCodeResourceDetails();
	  }

	  @Bean
	  @ConfigurationProperties("github.resource")
	  ResourceServerProperties githubResource() {
	  	return new ResourceServerProperties();
	  }
	  
	  private CsrfTokenRepository csrfTokenRepository() {
		  HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		  repository.setHeaderName("X-XSRF-TOKEN");
		  return repository;
	  }	  
	  
	  
	  @Bean
	  public FilterRegistrationBean oauth2ClientFilterRegistration(
	      OAuth2ClientContextFilter filter) {
	    FilterRegistrationBean registration = new FilterRegistrationBean();
	    registration.setFilter(filter);
	    registration.setOrder(-100);
	    return registration;
	  }
}
