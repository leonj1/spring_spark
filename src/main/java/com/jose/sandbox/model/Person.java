package com.jose.sandbox.model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

/**
 * Created for K and M Consulting LLC.
 * Created by Jose M Leon 2016
 **/
@Entity
public class Person {
    @Id @GeneratedValue private Long id;
    private String name;
    private String status;
}
