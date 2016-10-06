package com.jose.sandbox.repository;

import com.jose.sandbox.model.Person;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Created for K and M Consulting LLC.
 * Created by Jose M Leon 2016
 **/
public interface PersonRepository extends JpaRepository<Person, Long> {
}
