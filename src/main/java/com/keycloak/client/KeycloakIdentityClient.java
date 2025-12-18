package com.keycloak.client;

import com.keycloak.config.KeycloakProperties;
import com.keycloak.dto.*;
import com.keycloak.exceptions.KeycloakAdminException;
import com.keycloak.exceptions.UserAlreadyExistsException;
import jakarta.annotation.PostConstruct;
import jakarta.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(value = "app.idp.provider", havingValue = "keycloak", matchIfMissing = false)
@Slf4j
@RequiredArgsConstructor
public class KeycloakIdentityClient {

    private static final String ATTRIBUTE_PHONE = "phone_number";
    private static final String LOGIN_PIN = "custom:login_pin";
    private static final String QWIK_PIN = "custom:qwik_pin";
    private static final String CUSTOMER_ID_PROPERTY = "custom:das_customer_id";
    private static final String SCOPE_OIDC = "openid";
    private static final String GRANT_PASSWORD = "password";
    private static final String GRANT_REFRESH_TOKEN = "refresh_token";
    private static final String AUTH_PIN = "pin";
    private static final String AUTH_QWIK_PIN = "qwik_pin";
    private static final String AUTH_OTP_SEND = "otp_send";
    private static final String AUTH_OTP_VALIDATE = "otp_validate";
    private static final String MASTER = "master";
    private static final String SCOPE_OFFLINE_ACCESS = "openid offline_access";

    private final KeycloakAuthClient keycloakAuthClient;
    private final KeycloakProperties keycloakProperties;

    private Keycloak keycloak;
    private RealmResource realm;
    private UsersResource users;

    public UsersResource getUsersResource() {
        return users;
    }

    public RealmResource getRealmResource() {
        return realm;
    }

    @PostConstruct
    public void init() {
        // Check if admin credentials are provided (password grant) or use client credentials
        // Use client credentials grant (for service account clients)
        log.info("Initializing Keycloak admin client with client credentials grant");
        this.keycloak = KeycloakBuilder.builder()
                .serverUrl(keycloakProperties.getServerUrl())
                .realm(MASTER)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(keycloakProperties.getAdminClientId())
                .clientSecret(keycloakProperties.getAdminClientSecret())
                .build();

        this.realm = keycloak.realm(keycloakProperties.getRealm());
        this.users = realm.users();
        log.info("Keycloak admin client initialized for realm: {}", keycloakProperties.getRealm());
    }

    public IdpUser registerUser(String email, String password, String phone, String customerId)
            throws UserAlreadyExistsException {

        UserRepresentation user = new UserRepresentation();
        user.setUsername(customerId);
        user.setEnabled(true);
        user.setEmail(email);

        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put(CUSTOMER_ID_PROPERTY, Collections.singletonList(customerId));
        attributes.put(ATTRIBUTE_PHONE, Collections.singletonList(phone));
        user.setAttributes(attributes);

        Response response = users.create(user);

        if (response.getStatusInfo().getFamily() != Response.Status.Family.SUCCESSFUL) {
            if (response.getStatus() == Response.Status.CONFLICT.getStatusCode()) {
                throw new UserAlreadyExistsException("User already exists on Keycloak");
            }
            throw new KeycloakAdminException(
                    "User creation failed",
                    new RuntimeException(response.getStatusInfo().getReasonPhrase()));
        }

        String userId = response.getMetadata()
                .get("Location")
                .get(0)
                .toString()
                .substring(
                        response.getMetadata().get("Location").get(0).toString().lastIndexOf("users/") + 6);

        if (password != null) {
            CredentialRepresentation resetPassword = new CredentialRepresentation();
            resetPassword.setType(OAuth2Constants.PASSWORD);
            resetPassword.setValue(password);
            resetPassword.setTemporary(false);
            try {
                users.get(userId).resetPassword(resetPassword);
            } catch (Exception ex) {
                log.error("Error setting password for user " + customerId);
            }
        }

        return new IdpUser(userId, "Keycloak", Collections.emptyMap());
    }

    public IdpUser getUser(String email) {
        List<UserRepresentation> idpUsers = users.searchByEmail(email, true);
        if (idpUsers.isEmpty()) {
            throw new RuntimeException("User not found in Keycloak");
        }
        return new IdpUser(idpUsers.get(0).getId(), "Keycloak", Collections.emptyMap());
    }

    public void deleteUser(String email) {
        List<UserRepresentation> searchResults = users.searchByEmail(email, true);
        if (searchResults.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        UserRepresentation user = searchResults.get(0);
        users.delete(user.getId());
    }

    public LoginResponse userLogin(String email, String password) {
        try {
            TokenResponse response = keycloakAuthClient.token(new LoginRequest(
                    email,
                    password,
                    keycloakProperties.getClientId(),
                    keycloakProperties.getClientSecret(),
                    "openid",
                    "password"));

            return new LoginResponse(
                    response.getAccessToken(),
                    response.getRefreshToken(),
                    response.getIdToken(),
                    response.getExpiresIn(),
                    response.getTokenType());

        } catch (Exception ex) {
            throw new RuntimeException("Authentication failed for " + email, ex);
        }
    }

    public void setUserPassword(String email, String password) {
        try {
            UserRepresentation user = users.searchByEmail(email, true).get(0);
            CredentialRepresentation resetPassword = new CredentialRepresentation();
            resetPassword.setType(OAuth2Constants.PASSWORD);
            resetPassword.setValue(password);
            resetPassword.setTemporary(false);
            users.get(user.getId()).resetPassword(resetPassword);
        } catch (Exception ex) {
            throw new RuntimeException("User password update failed", ex);
        }
    }

    public LoginResponse refreshToken(String refreshToken, String email) {
        try {
            TokenResponse response = keycloakAuthClient.token(new RefreshTokenRequest(
                    keycloakProperties.getClientId(),
                    keycloakProperties.getClientSecret(),
                    GRANT_REFRESH_TOKEN,
                    refreshToken));

            return new LoginResponse(
                    response.getAccessToken(),
                    response.getRefreshToken(),
                    response.getIdToken(),
                    response.getExpiresIn(),
                    response.getTokenType());

        } catch (Exception ex) {
            throw new RuntimeException("Token refresh failed.", ex);
        }
    }

    public void setUserAttributes(String email, Map<String, String> newAttributes) {
        try {
            UserRepresentation user = users.searchByEmail(email, true).get(0);
            newAttributes.forEach((k, v) -> user.getAttributes().put(k, Collections.singletonList(v)));
            UserResource userResource = users.get(user.getId());
            userResource.update(user);
        } catch (Exception ex) {
            throw new RuntimeException("New attributes update failed", ex);
        }
    }

    public void removeUserAttributes(String username, String attribute) {
        throw new UnsupportedOperationException("Not yet implemented");
    }

    public void updateEmail(String idpUserName, String newEmail) {
        try {
            UserResource userResource = users.get(idpUserName);
            UserRepresentation userRepresentation = userResource.toRepresentation();
            userRepresentation.setEmail(newEmail);
            userResource.update(userRepresentation);
        } catch (Exception ex) {
            throw new RuntimeException("New attributes update failed", ex);
        }
    }

    public void updateUserLoginPin(String idpUserName, String loginPin) {
        try {
            UserResource userResource = users.get(idpUserName);
            UserRepresentation userRepresentation = userResource.toRepresentation();
            userRepresentation.getAttributes().put(LOGIN_PIN, Collections.singletonList(loginPin));
            userResource.update(userRepresentation);
        } catch (Exception ex) {
            throw new RuntimeException("New attributes update failed", ex);
        }
    }

    public LoginResponse pinLogin(String email, String loginPin) {
        try {
            TokenResponse response = keycloakAuthClient.token(new LoginRequest(
                    email,
                    null,
                    keycloakProperties.getClientId(),
                    keycloakProperties.getClientSecret(),
                    SCOPE_OIDC,
                    GRANT_PASSWORD,
                    AUTH_PIN,
                    loginPin));

            return new LoginResponse(
                    response.getAccessToken(),
                    response.getRefreshToken(),
                    response.getIdToken(),
                    response.getExpiresIn(),
                    response.getTokenType());

        } catch (Exception ex) {
            throw new RuntimeException("Authentication failed for " + email, ex);
        }
    }

    public LoginResponse qwikPinLogin(String email, String loginPin) {
        try {
            TokenResponse response = keycloakAuthClient.token(new LoginRequest(
                    email,
                    null,
                    keycloakProperties.getClientId(),
                    keycloakProperties.getClientSecret(),
                    SCOPE_OIDC,
                    GRANT_PASSWORD,
                    AUTH_QWIK_PIN,
                    loginPin));

            return new LoginResponse(
                    response.getAccessToken(),
                    response.getRefreshToken(),
                    response.getIdToken(),
                    response.getExpiresIn(),
                    response.getTokenType());

        } catch (Exception ex) {
            throw new RuntimeException("Authentication failed for " + email, ex);
        }
    }

    public void setQwikPin(String idpUserName, String loginPin) {
        try {
            UserResource userResource = users.get(idpUserName);
            UserRepresentation userRepresentation = userResource.toRepresentation();
            userRepresentation.getAttributes().put(QWIK_PIN, Collections.singletonList(loginPin));
            userResource.update(userRepresentation);
        } catch (Exception ex) {
            throw new RuntimeException("New attributes update failed", ex);
        }
    }

    public PasswordLessLoginInitiateResDTO passwordLessLogin(String email) {
        try {
            log.info("Password less login with keyClock for email " + email);
            OtpLoginResponse response = keycloakAuthClient.token(new OtpLoginRequest(
                    email,
                    keycloakProperties.getClientId(),
                    keycloakProperties.getClientSecret(),
                    "openid",
                    GRANT_PASSWORD,
                    AUTH_OTP_SEND));
            log.info("Password less login response from key-clock " + response);
            return new PasswordLessLoginInitiateResDTO(
                    email, response.getExecutionId() + ";" + response.getActionToken());

        } catch (Exception ex) {
            throw new RuntimeException("Authentication failed for " + email, ex);
        }
    }

    public LoginResponse passwordLessLoginValidate(PasswordLessLoginValidateDTO dto) {
        try {
            TokenResponse response = keycloakAuthClient.token(new LoginRequest(
                    dto.getPhoneNumber(),
                    null,
                    keycloakProperties.getClientId(),
                    keycloakProperties.getClientSecret(),
                    "openid",
                    GRANT_PASSWORD,
                    AUTH_OTP_VALIDATE,
                    dto.getOtp()));

            return new LoginResponse(
                    response.getAccessToken(),
                    response.getRefreshToken(),
                    response.getIdToken(),
                    response.getExpiresIn(),
                    response.getTokenType());

        } catch (Exception ex) {
            throw new RuntimeException("Authentication failed for " + dto.getPhoneNumber(), ex);
        }
    }

    public LoginResponse biometricPasswordLessLoginValidate(PasswordLessLoginValidateDTO dto) {
        try {
            TokenResponse response = keycloakAuthClient.token(new LoginRequest(
                    dto.getPhoneNumber(),
                    null,
                    keycloakProperties.getClientId(),
                    keycloakProperties.getClientSecret(),
                    SCOPE_OFFLINE_ACCESS,
                    GRANT_PASSWORD,
                    AUTH_OTP_VALIDATE,
                    dto.getOtp()));

            return new LoginResponse(
                    response.getAccessToken(),
                    response.getRefreshToken(),
                    response.getIdToken(),
                    response.getExpiresIn(),
                    response.getTokenType());

        } catch (Exception ex) {
            throw new RuntimeException("Authentication failed for ", ex);
        }
    }

    public void joinDsaGroup(Customer customer) {
        try {
            UserResource userResource = users.get(customer.getIdpUsername());
            GroupRepresentation dsaGroup = realm.groups().groups().stream()
                    .filter(group -> "dsa".equals(group.getName()))
                    .findFirst()
                    .orElse(null);

            if (dsaGroup != null) {
                userResource.joinGroup(dsaGroup.getId());
            }
        } catch (Exception ex) {
            throw new RuntimeException("Error joining Dsa group", ex);
        }
    }

    public void leaveDsaGroup(Customer customer) {
        try {
            UserResource userResource = users.get(customer.getIdpUsername());
            GroupRepresentation dsaGroup = realm.groups().groups().stream()
                    .filter(group -> "dsa".equals(group.getName()))
                    .findFirst()
                    .orElse(null);

            if (dsaGroup != null) {
                userResource.leaveGroup(dsaGroup.getId());
            }
        } catch (Exception ex) {
            throw new RuntimeException("Error leaving Dsa group", ex);
        }
    }

    public List<Long> listAllDsaMembers() {
        try {
            String groupId = realm.groups().groups().stream()
                    .filter(group -> "dsa".equals(group.getName()))
                    .findFirst()
                    .map(GroupRepresentation::getId)
                    .orElse(null);

            List<UserRepresentation> members = realm.groups().group(groupId).members();

            return members.stream()
                    .map(member -> {
                        List<String> customerIds = member.getAttributes().get("custom:das_customer_id");
                        if (customerIds != null && !customerIds.isEmpty()) {
                            try {
                                return Long.parseLong(customerIds.get(0));
                            } catch (NumberFormatException e) {
                                return null;
                            }
                        }
                        return null;
                    })
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

        } catch (Exception ex) {
            throw new RuntimeException("Error retrieving Dsa members", ex);
        }
    }
}
