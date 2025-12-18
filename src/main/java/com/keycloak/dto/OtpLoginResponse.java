package com.keycloak.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpLoginResponse {

    private String executionId;
    private String actionToken;

    @Override
    public String toString() {
        return "OtpLoginResponse{" + "executionId='"
                + executionId + '\'' + ", actionToken='"
                + actionToken + '\'' + '}';
    }
}
