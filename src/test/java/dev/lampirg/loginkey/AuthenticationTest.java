package dev.lampirg.loginkey;

import dev.lampirg.loginkey.controller.HelloController;
import dev.lampirg.test.loginkey.SecurityScanningConfiguration;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@WebMvcTest(HelloController.class)
@Import(SecurityScanningConfiguration.class)
@TestPropertySource(properties = {"version = 1.0"})
class AuthenticationTest {

    @Autowired
    private MockMvc mockMvc;
    private Resource json;

    @Test
    void givenNoBody() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .post("/login")
                )
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    void givenCorrectLogin() throws Exception {
        testWithJsonStatusAndResponseAsserter("logins/correct.json", HttpStatus.OK,
                MockMvcResultMatchers.header().string("Auth", Matchers.hasLength(15)));
    }

    @Test
    void givenIncorrectLogin() throws Exception {
        testWithJsonStatusAndResponseAsserter("logins/no-login.json", HttpStatus.UNAUTHORIZED,
                MockMvcResultMatchers.content().string("Username not found"));
    }

    @Test
    void givenIncorrectPassword() throws Exception {
        testWithJsonStatusAndResponseAsserter("logins/no-password.json", HttpStatus.UNAUTHORIZED,
                MockMvcResultMatchers.content().string("Password is invalid"));
    }

    @Test
    void givenIncorrectVersion() throws Exception {
        testWithJsonStatusAndResponseAsserter("logins/no-version.json", HttpStatus.FORBIDDEN,
                MockMvcResultMatchers.content().string("Invalid version. Expected 1.0 got 0.7"));
    }

    @Test
    void givenAllIncorrect() throws Exception {
        testWithJsonStatusAndResponseAsserter("logins/no-all.json", HttpStatus.UNAUTHORIZED,
                MockMvcResultMatchers.content().string("Username not found"));
    }

    private void testWithJsonStatusAndResponseAsserter(String path, HttpStatus status, ResultMatcher string) throws Exception {
        json = new ClassPathResource(path);
        mockMvc.perform(MockMvcRequestBuilders
                        .post("/login")
                        .content(json.getContentAsByteArray())
                )
                .andExpect(MockMvcResultMatchers.status().is(status.value()))
                .andExpect(string);
    }
}