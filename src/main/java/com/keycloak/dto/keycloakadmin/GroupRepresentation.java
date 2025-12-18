package com.keycloak.dto.keycloakadmin;

import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GroupRepresentation {

    private String id;
    private String name;
    private String path;
    private List<GroupRepresentation> subGroups;
    private Map<String, List<String>> attributes;
}
