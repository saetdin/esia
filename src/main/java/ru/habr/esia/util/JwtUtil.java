package ru.habr.esia.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class JwtUtil {

    private ObjectMapper mapper;

    @PostConstruct
    public void init() {
        this.mapper = new ObjectMapper();
    }

    public Map<String, Object> getTokenData(String token) {
        token = this.withoutBearerToken(token);
        String[] parts = token.split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

        Map<String, Object> jsonMap = new HashMap<String, Object>();
        try {
            // convert JSON string to Map
            jsonMap = this.mapper.readValue(payload,
                    new TypeReference<Map<String, Object>>() {
                    });
        } catch (Exception ex) {
            log.error("Ошибка парсинга токена: {}", ex.getMessage());
            throw new RuntimeException(ex);
        }
        return jsonMap;
    }

    public String getUserOid(String token) {
        return  String.valueOf(getTokenData(token).get("urn:esia:sbj_id"));
    }

    public String withoutBearerToken(String token) {
        if (token.startsWith("Bearer ")) {
            return token.substring(7);
        }
        return token;
    }

    public String withBearerToken(String token) {
        if (!token.startsWith("Bearer ")) {
            return String.format("Bearer %s", token);
        }
        return token;
    }
}
