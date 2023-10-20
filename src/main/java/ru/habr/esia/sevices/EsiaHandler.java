package ru.habr.esia.sevices;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import ru.habr.esia.exceptions.EsiaException;
import ru.habr.esia.util.JwtUtil;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
@Slf4j
public class EsiaHandler {

    @Autowired
    EsiaService esiaService;

    @Autowired
    private JwtUtil jwtUtil;

    public EsiaHandler(EsiaService esiaService, JwtUtil jwtUtil) {
        this.esiaService = esiaService;
        this.jwtUtil = jwtUtil;
    }

    public Mono<ServerResponse> test(ServerRequest request) {
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue("Cервис запущен"));
    }

    public Mono<ServerResponse> getClientSecret(ServerRequest request) throws EsiaException {
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(esiaService.getClientSecret()))
                .doOnError(error -> log.error("Ошибка получения client_secret"));
    }

    public Mono<ServerResponse> getUserUrl(ServerRequest request) throws EsiaException, UnsupportedEncodingException {
        return ServerResponse
                .temporaryRedirect(URI.create(esiaService.getUrl(request)))
                .build()
                ;
    }

    public Mono<ServerResponse> openEsiaSession(ServerRequest request) throws EsiaException, IOException {

        if (!request.queryParam("error").isPresent()) {
            String code = request.queryParam("code").orElse("code");
            String state = request.queryParam("state").orElse("state");
            return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                    .body(BodyInserters.fromPublisher(esiaService.openEsiaSession(code, state, request), LinkedHashMap.class))
                    .doOnError(error -> log.error("Ошибка открытия сессии"));
        } else {
            String error = request.queryParam("error").get();
            String errorDescription = request.queryParam("errorDescription").get();
            Map<String, Object> errorMap = new HashMap<>();
            errorMap.put("error", error);
            errorMap.put("errorDescription", errorDescription);
            return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                    .body(BodyInserters.fromValue(errorMap))
                    .doOnError(err -> log.error("Ошибка открытия сессии"));
        }


    }

    public Mono<ServerResponse> updateEsiaSession(ServerRequest request) throws EsiaException, IOException {
        String errorMessage = "Ошибка обновления сессии";
        if (request.queryParam("refresh_token").isPresent()) {
            ParameterizedTypeReference<LinkedHashMap<String, Object>> typeReference = new ParameterizedTypeReference<LinkedHashMap<String, Object>>(){};
            String refresh_token = request.queryParam("refresh_token").get();
            try {
                return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                        .body(BodyInserters.fromPublisher(esiaService.updateEsiaSession(refresh_token, typeReference, request), typeReference))
                        .doOnError(error -> log.error(errorMessage));
            } catch (EsiaException | IOException e) {
                return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                        .body(BodyInserters.fromValue(e.getMessage()))
                        .doOnError(err -> log.error(errorMessage));
            }
        } else {
            Map<String, Object> errorMap = new HashMap<>();
            errorMap.put("error", errorMessage);
            return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                    .body(BodyInserters.fromValue(errorMap))
                    .doOnError(err -> log.error(errorMessage));
        }


    }

    public Mono<ServerResponse> getUserInfo(ServerRequest request) throws EsiaException, IOException {
        String errorMessage = "Ошибка получения снилс";
        String causeError = "Отсутствует header access_token";
        String access_token = request.headers().firstHeader("access_token");
        if (null != access_token) {
            ParameterizedTypeReference<LinkedHashMap<String, Object>> typeReference = new ParameterizedTypeReference<LinkedHashMap<String, Object>>(){};
            String prn_oid = jwtUtil.getUserOid(access_token);
            try {
                return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                        .body(BodyInserters.fromPublisher(
                                esiaService
                                        .getUserInfo(prn_oid, jwtUtil.withBearerToken(access_token), typeReference), typeReference))
                        .doOnError(error -> log.error(errorMessage));
            } catch (Exception e) {
                return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                        .body(BodyInserters.fromValue(e.getMessage()))
                        .doOnError(err -> log.error(errorMessage));
            }
        } else {
            Map<String, Object> errorMap = new HashMap<>();
            errorMap.put("error", errorMessage);
            errorMap.put("cause", causeError);
            return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                    .body(BodyInserters.fromValue(errorMap))
                    .doOnError(err -> log.error(errorMessage));
        }


    }

    public Mono<ServerResponse> getCode(ServerRequest request) {
        Map<String, Object> map = new HashMap<>();
        if (!request.queryParam("error").isPresent()) {
            String code = request.queryParam("code").orElse("code");
            String state = request.queryParam("state").orElse("state");
            map.put("code", code);
            map.put("state", state);
        } else {
            String error = request.queryParam("error").get();
            String errorDescription = request.queryParam("errorDescription").orElse("error");
            map.put("error", error);
            map.put("errorDescription", errorDescription);

        }
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(map))
                .doOnError(err -> log.error("Ошибка открытия сессии"));
    }

}
