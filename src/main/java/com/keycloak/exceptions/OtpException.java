package com.keycloak.exceptions;

public class OtpException extends RuntimeException {
    public OtpException(String message) {
        super(message);
    }

    public OtpException(String message, Throwable cause) {
        super(message, cause);
    }
}
