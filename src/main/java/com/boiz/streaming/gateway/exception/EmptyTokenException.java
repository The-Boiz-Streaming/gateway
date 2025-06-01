package com.boiz.streaming.gateway.exception;

public class EmptyTokenException extends RuntimeException {

  private static final String EMPTY_TOKEN = "empty.token";

  public static EmptyTokenException of() {
      return new EmptyTokenException(EMPTY_TOKEN);
  }

  private EmptyTokenException(String message) {
      super(message);
  }
}
