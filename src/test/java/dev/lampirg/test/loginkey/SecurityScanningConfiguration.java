package dev.lampirg.test.loginkey;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.ComponentScan;

@TestConfiguration
@ComponentScan("dev.lampirg.loginkey.security")
public class SecurityScanningConfiguration {
}
