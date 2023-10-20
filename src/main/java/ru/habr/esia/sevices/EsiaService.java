package ru.habr.esia.sevices;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import ru.habr.esia.exceptions.EsiaException;
import ru.habr.esia.model.ClientSecretResponse;
import ru.infotecs.cms.output.CMSSignedDataOutputStream;
import ru.infotecs.crypto.ViPNetProvider;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.UUID;

/**
 * Отвечает за работу с ЕСИЯ. Документация АПИ ЕСИА (2.53): https://digital.gov.ru/ru/documents/6186/
 *
 * @version 1.0
 * @since 0.1.0
 */
@Slf4j
@Service
public class EsiaService {

    @Value("${server.port}")
    private String serverPort;
    @Value("${habr.esia.scope}")
    private String scope;
    @Value("${habr.esia.clientId}")
    private String clientId;
    @Value("${habr.esia.ketStorageDirectory}")
    private String ketStorageDirectory;
    @Value("${habr.esia.ketStoragePassword}")
    private String ketStoragePassword;
    @Value("${habr.esia.ketFile}")
    private String ketFile;
    @Value("${habr.esia.authCodeUlr}")
    private String authCodeUlr;
    @Value("${habr.esia.host}")
    private String esiaHost;
    @Value("${habr.esia.redirectUrl}")
    private String redirectUrl;

    @Autowired
    WebClient webClient;

    private PrivateKey privateKey;
    private X509Certificate certificate;

    @PreDestroy
    public void onDestroy() {
        Security.removeProvider(ViPNetProvider.NAME);
    }

    /**
     * Проверка необходимых настроек.
     */
    @PostConstruct
    public void init() throws NoSuchProviderException, KeyStoreException {
        log.info("Init EsiaService...");
        Security.addProvider(new ViPNetProvider());
        if (StringUtils.isEmpty(clientId)) {
            log.error("\t СlientId is not defined. Check property: habr.esia.clientId");
        }
        if (StringUtils.isEmpty(scope)) {
            log.error("\t Scope is not defined. Check property: habr.esia.scope");
        }
        if (StringUtils.isEmpty(ketStorageDirectory)) {
            log.error("\t KetStorageDirectory is not defined. Check property: habr.esia.ketStorageDirectory");
        }
        if (StringUtils.isEmpty(ketStoragePassword)) {
            log.error("\t KetStoragePassword is not defined. Check property: habr.esia.ketStoragePassword");
        }

        String ketFullPath = ketStorageDirectory + File.separator + ketFile;
        log.info("Init EsiaService done");

        KeyStore keyStore = KeyStore.getInstance(
                "ViPNetContainer3", // тип хранилища
                "ViPNet"           // название провайдера
        );

        String alias = "key";
        char[] password = ketStoragePassword.toCharArray();
        try (FileInputStream fis = new FileInputStream(new File(ketFullPath))) {
            keyStore.load(fis, ketStoragePassword.toCharArray());
            certificate = (X509Certificate) keyStore.getCertificate(alias);
            privateKey = (PrivateKey) keyStore.getKey(alias, password);
        } catch (Exception e) {
            log.error("Error while init EsiaService: " + e.getMessage());
        }
    }

    /**
     * Создаем и подписываем client_secret.
     * <client_secret> – подпись запроса в формате PKCS#7 detached signature в кодировке UTF-8 от значений четырех параметров HTTP–запроса: scope, timestamp,
     * clientId, state (без разделителей). <client_secret> должен быть закодирован в формате base64 url safe. Используемый для проверки подписи сертификат должен
     * быть предварительно зарегистрирован в ЕСИА и привязан к учетной записи системы-клиента в ЕСИА. ЕСИА поддерживает сертификаты в формате X.509. ЕСИА
     * поддерживает алгоритмы формирования электронной подписи RSA с длиной ключа 2048 и алгоритмом криптографического хэширования SHA-256, а также алгоритмы
     * электронной подписи ГОСТ Р 34.10-2001, ГОСТ Р 34.10-2012 и алгоритм криптографического хэширования ГОСТ Р 34.11-94.
     *
     * @return значение client_secret в виде строки Base64.
     * @throws EsiaException ошибка формирования/подписания
     */
    public ClientSecretResponse getClientSecret() throws EsiaException {
        try {
            ZonedDateTime now = ZonedDateTime.now();
            String timestamp = DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss xx").format(now);
            String state = UUID.randomUUID().toString();
            String msg = String.format("%s%s%s%s", scope, timestamp, clientId, state);
            byte[] messageAsByte = msg.getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream clientSecretOS = new ByteArrayOutputStream();
            try (
                    CMSSignedDataOutputStream signedStream = new CMSSignedDataOutputStream(clientSecretOS)) {
                signedStream.addCertificates(certificate);
                signedStream.addSigner(privateKey, certificate);
                signedStream.write(messageAsByte, 0, messageAsByte.length);
            }
            byte[] utf = clientSecretOS.toByteArray();
            String clientSecret = new String(Base64.getEncoder().encode(utf));
            String clientSecretUrlEncoded = clientSecret.replace("+", "-")
                    .replace("/", "_")
                    .replace("=", "");
            log.debug("Generated new clientSecret:" + clientSecretUrlEncoded);
            return new ClientSecretResponse(timestamp, state, scope, clientSecretUrlEncoded);
        } catch (Exception error) {
            throw new EsiaException(error);
        }
    }


    /**
     * Генерация ссылки для получения авторизационного кода
     *
     * @param request
     * @return ссылка
     * @throws EsiaException
     * @throws UnsupportedEncodingException
     */
    public String getUrl(ServerRequest request) throws EsiaException, UnsupportedEncodingException {
        ClientSecretResponse clientSecretResponse = this.getClientSecret();
        String type = request.pathVariable("redirect");
        String timestampUrlEncoded = getTimestampUrlEncoded(clientSecretResponse);
        String redirectUrlEncoded = getRedirectUrlEncoded(String.format("http://%s:%s/%s",
                request.uri().getHost(),
                request.uri().getPort(),
                type));
        UriComponentsBuilder accessTokenRequestBuilder = UriComponentsBuilder.fromHttpUrl(this.authCodeUlr)
                .queryParam("client_id", URLEncoder.encode(clientId, StandardCharsets.UTF_8.toString()))
                .queryParam("response_type", URLEncoder.encode("code", StandardCharsets.UTF_8.toString()))
                .queryParam("access_type", URLEncoder.encode("offline", StandardCharsets.UTF_8.toString()))
                .queryParam("scope", URLEncoder.encode(scope, StandardCharsets.UTF_8.toString()))
                .queryParam("state", URLEncoder.encode(clientSecretResponse.getState(), StandardCharsets.UTF_8.toString()))
                .queryParam("client_secret", URLEncoder.encode(clientSecretResponse.getClient_secret(), StandardCharsets.UTF_8.toString()));
        String url = accessTokenRequestBuilder.toUriString();
        url += "&timestamp=" + timestampUrlEncoded;
        url += "&redirect_uri=" + redirectUrlEncoded;
        return url;
    }

    public Mono<LinkedHashMap> openEsiaSession(String code, String state, ServerRequest request) throws EsiaException, IOException {
        ClientSecretResponse clientSecretResponse = this.getClientSecret();
        String timestampUrlEncoded = getTimestampUrlEncoded(clientSecretResponse);
        String redirectUrlEncoded = getRedirectUrlEncoded(String.format("http://%s:%s",
                request.uri().getHost(),
                request.uri().getPort()));
        StringBuilder formData = new StringBuilder("&");
        formData.append(URLEncoder.encode("grant_type", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode("authorization_code", StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("client_id", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("code", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(code, StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("state", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(clientSecretResponse.getState(), StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("token_type", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode("Bearer", StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("scope", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("refresh_token", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(clientSecretResponse.getState(), StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("client_secret", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(clientSecretResponse.getClient_secret(), StandardCharsets.UTF_8.toString())).append("&");
        formData.append("timestamp").append("=").append(timestampUrlEncoded).append("&");
        formData.append(URLEncoder.encode("redirect_uri", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(redirectUrlEncoded, StandardCharsets.UTF_8.toString()));

        return webClient
                .post()
                .uri(uriBuilder ->
                        uriBuilder.host(esiaHost)
                                .path("/aas/oauth2/te")
                                .build()
                )
                .header("Content-Type", "application/x-www-form-urlencoded")
                .bodyValue(formData.toString())
                .retrieve()
                .bodyToMono(LinkedHashMap.class)
                .timeout(Duration.ofMillis(30000))
                .onErrorResume(e -> {
                    LinkedHashMap<String, Object> errorMap = new LinkedHashMap<>();
                    errorMap.put("error", e.getMessage());
                    return Mono.just(errorMap);
                })
                .doOnError(error -> {
                    log.error("An error has occurred {}", error.getMessage());
                    throw new RuntimeException();
                });
    }

    public Mono<LinkedHashMap<String, Object>> updateEsiaSession(String refreshToken, ParameterizedTypeReference<LinkedHashMap<String, Object>> typeReference, ServerRequest request) throws EsiaException, IOException {

        ClientSecretResponse clientSecretResponse = this.getClientSecret();
        String timestampUrlEncoded = getTimestampUrlEncoded(clientSecretResponse);

        String redirectUrlEncoded = getRedirectUrlEncoded(String.format("http://%s:%s",
                request.uri().getHost(),
                request.uri().getPort()));

        StringBuilder formData = new StringBuilder("&");
        formData.append(URLEncoder.encode("client_id", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("client_secret", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(clientSecretResponse.getClient_secret(), StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("refresh_token", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(refreshToken, StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("scope", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("grant_type", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode("refresh_token", StandardCharsets.UTF_8.toString())).append("&");
        formData.append(URLEncoder.encode("state", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(clientSecretResponse.getState(), StandardCharsets.UTF_8.toString())).append("&");
        formData.append("timestamp").append("=").append(timestampUrlEncoded).append("&");
        formData.append(URLEncoder.encode("redirect_uri", StandardCharsets.UTF_8.toString())).append("=").append(URLEncoder.encode(redirectUrlEncoded, StandardCharsets.UTF_8.toString()));

        return webClient
                .post()
                .uri(uriBuilder ->
                        uriBuilder.host(esiaHost)
                                .path("/aas/oauth2/te")
                                .build()
                )
                .header("Content-Type", "application/x-www-form-urlencoded")
                .bodyValue(formData.toString())
                .retrieve()
                .bodyToMono(typeReference)
                .timeout(Duration.ofMillis(30000))
                .onErrorResume(e -> {
                    LinkedHashMap<String, Object> errorMap = new LinkedHashMap<>();
                    errorMap.put("error", e.getMessage());
                    return Mono.just(errorMap);
                })
                .doOnError(error -> {
                    log.error("An error has occurred {}", error.getMessage());
                    throw new RuntimeException();
                });
    }


    private static String getTimestampUrlEncoded(ClientSecretResponse clientSecretResponse) {
        return clientSecretResponse.getTimestamp()
                .replace("+", "%2B")
                .replace(":", "%3A")
                .replace(" ", "+");
    }


    private String getRedirectUrlEncoded(String redirect) {
        if (null == redirect) {
            redirect = redirectUrl;
        }
        return redirect
                .replace(":", "%3A")
                .replace("/", "%2F");
    }

    public Mono<LinkedHashMap<String, Object>> getUserInfo(String prn_oid, String token, ParameterizedTypeReference<LinkedHashMap<String, Object>> typeReference) {
        return webClient
                .get()
                .uri(uriBuilder ->
                        uriBuilder.host(esiaHost)
                                .path("rs/prns/{prn_oid}")
                                .build(prn_oid)
                )
                .headers(httpHeaders -> {
                    httpHeaders.setContentType(MediaType.APPLICATION_JSON);
                    httpHeaders.set("Authorization", token);
                })
                .retrieve()
                .bodyToMono(typeReference)
                .timeout(Duration.ofMillis(30000))
                .onErrorResume(e -> {
                    LinkedHashMap<String, Object> errorMap = new LinkedHashMap<>();
                    errorMap.put("error", e.getMessage());
                    return Mono.just(errorMap);
                })
                .doOnError(error -> {
                    log.error("An error has occurred {}", error.getMessage());
                    throw new RuntimeException();
                });
    }


}
