package com.kdemo.facebook.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

@Api(value="Rest Boot Oauth Example")
@RestController
public class MainController
{
	@ApiOperation(notes="Method used for printing a string", value = "/hello", code=200)
	@RequestMapping(value = "/hello", method = RequestMethod.GET)
	public String hello()
	{
		return "Hello from SPRING!";
	}
	
	@ApiOperation(notes="Method used to echo a value", value = "/echo", code=200)
	@RequestMapping(value = "/echo", method = RequestMethod.GET)
	public String echo(
			@ApiParam(name = "name", value = "a parameter", required = true) @RequestParam(value="name") String name
			)
	{
		return name;
	}
	
	@ApiOperation(notes="Method used for getting the principal", value = "/hello", code=200)
	@RequestMapping(value = "/user", method = RequestMethod.GET)
	public Principal user(Principal p)
	{
		return p;
	}
}
