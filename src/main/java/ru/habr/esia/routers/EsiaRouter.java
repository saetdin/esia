package ru.habr.esia.routers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import ru.habr.esia.exceptions.EsiaException;
import ru.habr.esia.sevices.EsiaHandler;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import static org.springframework.web.reactive.function.server.RequestPredicates.*;

@Slf4j
@Configuration(proxyBeanMethods = false)
public class EsiaRouter {
    @Bean
    public RouterFunction<ServerResponse> route(EsiaHandler esiaHandler) {

        return RouterFunctions
                .route(GET("/check").and(accept(MediaType.TEXT_PLAIN)), esiaHandler::test)
                .andRoute(
                        GET("/oauth/esia/{redirect}")
                                .and(accept(MediaType.APPLICATION_JSON)),
                        serverRequest -> {
                            try {
                                return esiaHandler.getUserUrl(serverRequest);
                            } catch (EsiaException | UnsupportedEncodingException e) {
                                log.error("Error while getUserUrl: " + e.getMessage());
                                throw new RuntimeException(e);
                            }
                        }
                )
                .andRoute(
                        GET("/session")
                                .and(accept(MediaType.APPLICATION_JSON)),
                        serverRequest -> {
                            try {
                                return esiaHandler.openEsiaSession(serverRequest);
                            } catch (EsiaException | IOException e) {
                                throw new RuntimeException(e);
                            }
                        }
                )
                .andRoute(
                        POST("/session")
                                .and(accept(MediaType.APPLICATION_JSON)),
                        serverRequest -> {
                            try {
                                return esiaHandler.openEsiaSession(serverRequest);
                            } catch (EsiaException | IOException e) {
                                throw new RuntimeException(e);
                            }
                        }
                )
                .andRoute(
                        POST("/update")
                                .and(accept(MediaType.APPLICATION_JSON)),
                        serverRequest -> {
                            try {
                                return esiaHandler.updateEsiaSession(serverRequest);
                            } catch (EsiaException | IOException e) {
                                throw new RuntimeException(e);
                            }
                        }
                )
                .andRoute(
                        POST("/user")
                                .and(accept(MediaType.APPLICATION_JSON)),
                        serverRequest -> {
                            try {
                                return esiaHandler.getUserInfo(serverRequest);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                )
                .andRoute(
                        GET("/code")
                                .and(accept(MediaType.APPLICATION_JSON)),
                        esiaHandler::getCode
                )
                ;
    }
}
