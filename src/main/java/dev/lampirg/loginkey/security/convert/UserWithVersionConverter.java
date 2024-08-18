package dev.lampirg.loginkey.security.convert;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.lampirg.loginkey.model.UserDto;
import dev.lampirg.loginkey.security.token.UserWithVersionAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class UserWithVersionConverter implements AuthenticationConverter {

    private final ObjectMapper objectMapper;
    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!request.getMethod().equals(HttpMethod.POST.name())) {
            return null;
        }
        try {
            UserDto userDto = objectMapper.readValue(request.getReader(), UserDto.class);
            return new UserWithVersionAuthenticationToken(userDto.getUsername(),
                    userDto.getPassword(), userDto.getVersion());
        } catch (IOException e) {
            return null;
        }
    }
}
