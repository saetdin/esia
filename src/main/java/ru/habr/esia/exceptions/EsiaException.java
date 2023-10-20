package ru.habr.esia.exceptions;

/**
 * Ошибка при работе с сервисов ЕСИА.
 *
 * @version 1.0
 * @since 0.1.0
 */
public class EsiaException extends Exception {

  private static final long serialVersionUID = -5442615607180944074L;

  public EsiaException() {
    super();
  }

  public EsiaException(String message) {
    super(message);
  }

  public EsiaException(String message, Throwable cause) {
    super(message, cause);
  }

  public EsiaException(Throwable cause) {
    super(cause);
  }

  protected EsiaException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
