package com.jose.sandbox.controllers;

import com.jose.sandbox.controllers.routes.PersonRoute;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

import static spark.Spark.get;

@Component
public class SimpleController {

    @Autowired
    PersonRoute helloRoute;

    public SimpleController() {}

    public SimpleController(PersonRoute helloRoute) {
        this.helloRoute = helloRoute;
    }

    @PostConstruct
    public void init() {
        get("/hello", this.helloRoute);
    }
}
