package com.keycloak.dto;

import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class IdpUser {
    private String userId;
    private String keycloak;
    private Map<Object, Object> objectObjectMap;
}
