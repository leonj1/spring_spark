package com.jose.sandbox.controllers;

import com.despegar.sparkjava.test.SparkClient;
import com.despegar.sparkjava.test.SparkServer;
import com.github.springtestdbunit.DbUnitTestExecutionListener;
import com.github.springtestdbunit.annotation.DatabaseSetup;
import com.jose.sandbox.controllers.routes.CheckNumbersRoute;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.transaction.annotation.Transactional;
import spark.Response;
import spark.servlet.SparkApplication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@TestExecutionListeners({
        DependencyInjectionTestExecutionListener.class,
        DbUnitTestExecutionListener.class
})
@DatabaseSetup("persons-entities.xml")
@Transactional
public class CheckNumbersControllerTest {

    @Configuration
    @ComponentScan(basePackages = {"com.jose.sandbox"})
    static class SomeConfig {

        // because @PropertySource doesn't work in annotation only land
        @Bean
        public PropertyPlaceholderConfigurer propConfig() {
            PropertyPlaceholderConfigurer ppc = new PropertyPlaceholderConfigurer();
            ppc.setLocation(new ClassPathResource("application.properties"));
            return ppc;
        }
    }

    @Component
    public static class TestControllerTestApplication implements SparkApplication {

        @Autowired CheckNumbersRoute checkNumbersRoute;

        @Override
        public void init() {
            new CheckNumbersController(this.checkNumbersRoute);
        }
    }

    @ClassRule
    public static SparkServer<CheckNumbersControllerTest.TestControllerTestApplication> testServer
            = new SparkServer<>(CheckNumbersControllerTest.TestControllerTestApplication.class, 4567);

    @Test
    public void one() throws Exception {
        // given
        String payload = "{ \"numbers\": \"1 2 3 4 5\", \"multiplier\": \"10\", \"Mega Millions\", \"ticket_date\": \"2016-10-10\" }";

        // when
        SparkClient.UrlResponse response = testServer.getClient().doMethod("POST", "/private/check", payload);

        // then
        String expected = "";
        assertEquals(200, response.status);
        assertEquals(expected, response.body);
        assertNotNull(testServer.getApplication());
    }

    @Mock
    Response response;
}
