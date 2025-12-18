package com.keycloak.exceptions;

public class UserSyncException extends RuntimeException {

    public UserSyncException(String message) {
        super(message);
    }

    public UserSyncException(String message, Throwable cause) {
        super(message, cause);
    }
}
