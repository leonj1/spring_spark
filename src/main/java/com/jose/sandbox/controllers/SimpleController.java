package com.jose.sandbox.controllers;

import com.jose.sandbox.controllers.routes.CheckNumbersRoute;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

import static spark.Spark.post;

@Component
public class CheckNumbersController {

    @Autowired @NonNull CheckNumbersRoute checkNumbersRoute;

    @PostConstruct
    public void init() {
        post("/private/check", this.checkNumbersRoute);
    }
}
