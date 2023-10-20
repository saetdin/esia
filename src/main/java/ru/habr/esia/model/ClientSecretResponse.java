package ru.habr.esia.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

/**
 * Ответ на запрос client_secret.
 *
 * @version 1.0
 * @since 0.1.0
 */
@Getter
@Setter
@AllArgsConstructor
public class ClientSecretResponse {

  private String timestamp;
  private String state;
  private String scope;
  private String client_secret;

}
