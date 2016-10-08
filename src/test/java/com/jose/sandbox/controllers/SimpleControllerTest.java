package com.jose.sandbox.controllers;

import com.despegar.sparkjava.test.SparkClient;
import com.despegar.sparkjava.test.SparkServer;
import com.github.springtestdbunit.DbUnitTestExecutionListener;
import com.github.springtestdbunit.annotation.DatabaseSetup;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
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
import spark.Response;
import spark.servlet.SparkApplication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.springframework.test.context.TestExecutionListeners.MergeMode.MERGE_WITH_DEFAULTS;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@TestExecutionListeners(
        value = {
                DependencyInjectionTestExecutionListener.class,
                DbUnitTestExecutionListener.class
        },
        mergeMode = MERGE_WITH_DEFAULTS)
@DatabaseSetup("persons-entities.xml")
public class SimpleControllerTest {

    @Configuration
    @ComponentScan(basePackages = {"com.jose.sandbox"})
    static class SomeConfig {

        @Bean
        public static PropertyPlaceholderConfigurer propConfig() {
            PropertyPlaceholderConfigurer ppc = new PropertyPlaceholderConfigurer();
            ppc.setLocation(new ClassPathResource("application.properties"));
            return ppc;
        }
    }

    @Component
    public static class TestControllerTestApplication implements SparkApplication {

        @Override
        public void init() {
        }
    }

    @ClassRule
    public static SparkServer<SimpleControllerTest.TestControllerTestApplication> testServer
            = new SparkServer<>(SimpleControllerTest.TestControllerTestApplication.class, 4567);

    @Test
    public void verifyGetAllPeople() throws Exception {
        // given
        String payload = null;

        // when
        SparkClient.UrlResponse response = testServer.getClient().doMethod("GET", "/people/count", payload);

        // then
        int expected = 3; // because that's how many exist in persons-entities.xml
        assertEquals(200, response.status);
        assertEquals(expected, Integer.parseInt(response.body));
        assertNotNull(testServer.getApplication());
    }

    @Mock
    Response response;
}
