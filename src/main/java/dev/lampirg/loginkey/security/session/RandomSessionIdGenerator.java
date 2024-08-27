package dev.lampirg.loginkey.security.session;

import org.springframework.stereotype.Service;

import java.util.random.RandomGenerator;

@Service
public class RandomSessionIdGenerator {

    private final RandomGenerator randomGenerator = RandomGenerator.getDefault();


    public String generateKey() {
        return randomGenerator.ints('0', 'z' + 1)
                .filter(value -> Character.isAlphabetic(value) || Character.isDigit(value))
                .limit(15)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

}
