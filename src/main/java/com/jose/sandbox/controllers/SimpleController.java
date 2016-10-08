package com.jose.sandbox.controllers;

import com.jose.sandbox.controllers.routes.PersonRoute;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

import static spark.Spark.get;

@Component
public class SimpleController {

    @Autowired PersonRoute personRoute;

    public SimpleController() {}

    public SimpleController(PersonRoute personRoute) {
        this.personRoute = personRoute;
    }

    @PostConstruct
    public void init() {
        get("/people/count", this.personRoute);
    }
}
