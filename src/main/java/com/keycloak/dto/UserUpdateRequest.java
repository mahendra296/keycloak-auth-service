package com.keycloak.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserUpdateRequest {

    private String firstName;
    private String lastName;
    private String phone;
    private String address;
    private String city;
    private String country;
    private String postalCode;
}
