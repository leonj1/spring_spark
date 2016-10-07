package com.jose.sandbox.controllers;

import com.jose.sandbox.controllers.routes.PersonRoute;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

import static spark.Spark.get;

@Component
public class SimpleController {

    // #2 debug point 2, also shows this as NULL
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
