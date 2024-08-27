package dev.lampirg.loginkey;

import dev.lampirg.loginkey.controller.HelloController;
import dev.lampirg.loginkey.security.session.RandomSessionIdGenerator;
import dev.lampirg.test.loginkey.SecurityScanningConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@WebMvcTest(HelloController.class)
@Import(SecurityScanningConfiguration.class)
@TestPropertySource(properties = {"version = 1.0"})
class HeaderAuthorizationTest {


    @Autowired
    private MockMvc mockMvc;
    @MockBean
    private RandomSessionIdGenerator sessionIdGenerator;


    @Autowired
    private SessionRegistry toTearDownRegistry;

    @BeforeEach
    void setUp() throws Exception {
        mockAuthorization("123456789ABCDEF");
    }

    private void mockAuthorization(String key) throws Exception {
        Mockito.when(sessionIdGenerator.generateKey()).thenReturn(key);
        Resource json = new ClassPathResource("logins/correct.json");
        mockMvc.perform(MockMvcRequestBuilders
                        .post("/login")
                        .content(json.getContentAsByteArray())
                )
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string("Auth", key));
    }

    @AfterEach
    void tearDown() {
        toTearDownRegistry.getAllPrincipals().stream()
                .flatMap(o -> toTearDownRegistry.getAllSessions(o, true).stream())
                .map(SessionInformation::getSessionId)
                .forEach(toTearDownRegistry::removeSessionInformation);
    }

    @Test
    void givenCorrectHeader() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders.post("/login")
                                .header("Auth", "123456789ABCDEF")
                )
                .andExpect(MockMvcResultMatchers.status().isOk());
    }

    @Test
    void givenNoHeader() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/login"))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    void givenIncorrectHeader() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders.post("/login")
                                .header("Auth", "FEDCBA987654321")
                )
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    void givenNewHeader() throws Exception {
        mockAuthorization("987654321FEDCBA");
        mockMvc.perform(
                        MockMvcRequestBuilders.post("/login")
                                .header("Auth", "987654321FEDCBA")
                )
                .andExpect(MockMvcResultMatchers.status().isOk());
    }

    @Test
    void givenOldHeader() throws Exception {
        mockAuthorization("987654321FEDCBA");
        mockMvc.perform(
                        MockMvcRequestBuilders.post("/login")
                                .header("Auth", "123456789ABCDEF")
                )
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }
}
