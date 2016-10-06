package com.jose.sandbox.controllers.routes;

import com.jose.sandbox.repository.PersonRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import spark.Request;
import spark.Response;
import spark.Route;

@Component
public class PersonRoute implements Route {

    @Autowired
    PersonRepository personRepository;

    @Override
    public Object handle(Request request, Response response) throws Exception {
        response.status(200);
        return this.personRepository.findAll().size();
    }
}
