package com.kdemo.facebook.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.support.SpringBootServletInitializer;

@SpringBootApplication(scanBasePackages = "com.kdemo.facebook")
public class SocialApplication extends SpringBootServletInitializer 
{
	@Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) 
	{
        return application.sources(SocialApplication.class);
    }
	
	public static void main(String[] args) 
	{
		SpringApplication.run(SocialApplication.class, args);
	}
}
