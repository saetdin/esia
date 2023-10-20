package ru.habr.esia.exceptions;

import lombok.Getter;

/**
 * Ошибка при работе с внешними сервисами.
 *
 * @version 1.0
 * @since 0.3.0
 */
public class ExternalServiceException extends Exception {


  private static final long serialVersionUID = 8118931603896841532L;
  @Getter
  private String userMessage;
  @Getter
  private Integer code = 500;

  public ExternalServiceException() {
    super();
  }

  public ExternalServiceException(String message) {
    super(message);
  }
  public ExternalServiceException(String message, Integer code) {
    super(message);
    this.code = code;
  }

  public ExternalServiceException(String message, String userMessage) {
    super(message);
    this.userMessage = userMessage;
  }

  public ExternalServiceException(String message, Throwable cause) {
    super(message, cause);
  }

  public ExternalServiceException(Throwable cause) {
    super(cause);
  }

  protected ExternalServiceException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
