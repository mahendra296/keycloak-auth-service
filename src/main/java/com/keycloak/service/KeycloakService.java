package com.keycloak.service;

import com.keycloak.client.KeycloakIdentityClient;
import com.keycloak.config.KeycloakProperties;
import com.keycloak.dto.*;
import com.keycloak.dto.keycloakadmin.GroupRepresentation;
import com.keycloak.dto.keycloakadmin.RoleRepresentation;
import com.keycloak.exceptions.AuthenticationException;
import com.keycloak.exceptions.UserAlreadyExistsException;
import com.keycloak.exceptions.UserNotFoundException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Service layer for Keycloak identity operations.
 * Wraps KeycloakIdentityClient and provides business logic for authentication flows.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(value = "app.idp.provider", havingValue = "keycloak", matchIfMissing = false)
public class KeycloakService {

    private final KeycloakIdentityClient keycloakIdentityClient;
    private final KeycloakProperties keycloakProperties;

    // ==================== LOGIN METHODS ====================

    /**
     * Authenticate user with email/username and password.
     *
     * @param email    User's email or username
     * @param password User's password
     * @return LoginResponse containing access, refresh, and id tokens
     * @throws AuthenticationException if authentication fails
     */
    public LoginResponse login(String email, String password) {
        log.info("Attempting password login for user: {}", email);
        validateNotBlank(email, "Email/username is required");
        validateNotBlank(password, "Password is required");

        try {
            LoginResponse response = keycloakIdentityClient.userLogin(email, password);
            log.info("Password login successful for user: {}", email);
            return response;
        } catch (Exception e) {
            log.error("Password login failed for user: {}", email, e);
            throw new AuthenticationException("Invalid username or password", e);
        }
    }

    /**
     * Authenticate user with PIN.
     *
     * @param email    User's email or username
     * @param loginPin User's login PIN
     * @return LoginResponse containing tokens
     * @throws AuthenticationException if authentication fails
     */
    public LoginResponse loginWithPin(String email, String loginPin) {
        log.info("Attempting PIN login for user: {}", email);
        validateNotBlank(email, "Email/username is required");
        validateNotBlank(loginPin, "Login PIN is required");

        try {
            LoginResponse response = keycloakIdentityClient.pinLogin(email, loginPin);
            log.info("PIN login successful for user: {}", email);
            return response;
        } catch (Exception e) {
            log.error("PIN login failed for user: {}", email, e);
            throw new AuthenticationException("Invalid PIN", e);
        }
    }

    /**
     * Authenticate user with QWIK PIN.
     *
     * @param email   User's email or username
     * @param qwikPin User's QWIK PIN
     * @return LoginResponse containing tokens
     * @throws AuthenticationException if authentication fails
     */
    public LoginResponse loginWithQwikPin(String email, String qwikPin) {
        log.info("Attempting QWIK PIN login for user: {}", email);
        validateNotBlank(email, "Email/username is required");
        validateNotBlank(qwikPin, "QWIK PIN is required");

        try {
            LoginResponse response = keycloakIdentityClient.qwikPinLogin(email, qwikPin);
            log.info("QWIK PIN login successful for user: {}", email);
            return response;
        } catch (Exception e) {
            log.error("QWIK PIN login failed for user: {}", email, e);
            throw new AuthenticationException("Invalid QWIK PIN", e);
        }
    }

    // ==================== PASSWORDLESS LOGIN METHODS ====================

    /**
     * Initiate passwordless login by sending OTP to user.
     *
     * @param email User's email or phone number
     * @return PasswordLessLoginInitiateResDTO containing session code for validation
     * @throws AuthenticationException if initiation fails
     */
    public PasswordLessLoginInitiateResDTO initiatePasswordlessLogin(String email) {
        log.info("Initiating passwordless login for user: {}", email);
        validateNotBlank(email, "Email/phone number is required");

        try {
            PasswordLessLoginInitiateResDTO response = keycloakIdentityClient.passwordLessLogin(email);
            log.info("Passwordless login initiated for user: {}", email);
            return response;
        } catch (Exception e) {
            log.error("Passwordless login initiation failed for user: {}", email, e);
            throw new AuthenticationException("Failed to initiate passwordless login", e);
        }
    }

    /**
     * Validate passwordless login with OTP.
     *
     * @param phoneNumber User's phone number
     * @param sessionCode Session code from initiation
     * @param otp         OTP entered by user
     * @return LoginResponse containing tokens
     * @throws AuthenticationException if validation fails
     */
    public LoginResponse validatePasswordlessLogin(String phoneNumber, String sessionCode, String otp) {
        log.info("Validating passwordless login for user: {}", phoneNumber);
        validateNotBlank(phoneNumber, "Phone number is required");
        validateNotBlank(otp, "OTP is required");

        try {
            PasswordLessLoginValidateDTO dto = PasswordLessLoginValidateDTO.builder()
                    .phoneNumber(phoneNumber)
                    .sessionCode(sessionCode)
                    .otp(otp)
                    .isBiometricEnabled(false)
                    .build();

            LoginResponse response = keycloakIdentityClient.passwordLessLoginValidate(dto);
            log.info("Passwordless login validation successful for user: {}", phoneNumber);
            return response;
        } catch (Exception e) {
            log.error("Passwordless login validation failed for user: {}", phoneNumber, e);
            throw new AuthenticationException("Invalid OTP or session expired", e);
        }
    }

    /**
     * Validate passwordless login with biometric enabled (offline access).
     *
     * @param phoneNumber User's phone number
     * @param sessionCode Session code from initiation
     * @param otp         OTP entered by user
     * @return LoginResponse containing tokens with offline_access scope
     * @throws AuthenticationException if validation fails
     */
    public LoginResponse validateBiometricPasswordlessLogin(String phoneNumber, String sessionCode, String otp) {
        log.info("Validating biometric passwordless login for user: {}", phoneNumber);
        validateNotBlank(phoneNumber, "Phone number is required");
        validateNotBlank(otp, "OTP is required");

        try {
            PasswordLessLoginValidateDTO dto = PasswordLessLoginValidateDTO.builder()
                    .phoneNumber(phoneNumber)
                    .sessionCode(sessionCode)
                    .otp(otp)
                    .isBiometricEnabled(true)
                    .build();

            LoginResponse response = keycloakIdentityClient.biometricPasswordLessLoginValidate(dto);
            log.info("Biometric passwordless login validation successful for user: {}", phoneNumber);
            return response;
        } catch (Exception e) {
            log.error("Biometric passwordless login validation failed for user: {}", phoneNumber, e);
            throw new AuthenticationException("Invalid OTP or session expired", e);
        }
    }

    // ==================== REGISTRATION METHODS ====================

    /**
     * Register a new user in Keycloak.
     *
     * @param request User registration request containing user details
     * @return IdpUser containing the created user's ID
     * @throws UserAlreadyExistsException if user already exists
     * @throws AuthenticationException    if registration fails
     */
    public IdpUser registerUser(UserRegistrationRequest request) throws UserAlreadyExistsException {
        log.info("Registering new user with email: {}", request.getEmail());
        validateRegistrationRequest(request);

        try {
            String customerId = generateCustomerId();
            IdpUser idpUser = keycloakIdentityClient.registerUser(
                    request.getEmail(), request.getPassword(), request.getPhone(), customerId);

            // Set additional user attributes if provided
            updateUserProfile(idpUser.getUserId(), request);

            log.info("User registered successfully with ID: {}", idpUser.getUserId());
            return idpUser;
        } catch (UserAlreadyExistsException e) {
            log.warn("User already exists: {}", request.getEmail());
            throw e;
        } catch (Exception e) {
            log.error("User registration failed for email: {}", request.getEmail(), e);
            throw new AuthenticationException("User registration failed", e);
        }
    }

    /**
     * Register a new user with minimal information.
     *
     * @param email      User's email
     * @param password   User's password
     * @param phone      User's phone number
     * @param customerId Custom identifier for the user
     * @return IdpUser containing the created user's ID
     * @throws UserAlreadyExistsException if user already exists
     */
    public IdpUser registerUser(String email, String password, String phone, String customerId)
            throws UserAlreadyExistsException {
        log.info("Registering new user with email: {}", email);
        validateNotBlank(email, "Email is required");
        validateNotBlank(password, "Password is required");

        if (!StringUtils.hasText(customerId)) {
            customerId = generateCustomerId();
        }

        try {
            IdpUser idpUser = keycloakIdentityClient.registerUser(email, password, phone, customerId);
            log.info("User registered successfully with ID: {}", idpUser.getUserId());
            return idpUser;
        } catch (UserAlreadyExistsException e) {
            log.warn("User already exists: {}", email);
            throw e;
        } catch (Exception e) {
            log.error("User registration failed for email: {}", email, e);
            throw new AuthenticationException("User registration failed", e);
        }
    }

    // ==================== TOKEN MANAGEMENT ====================

    /**
     * Refresh access token using refresh token.
     *
     * @param refreshToken Valid refresh token
     * @return LoginResponse containing new tokens
     * @throws AuthenticationException if refresh fails
     */
    public LoginResponse refreshToken(String refreshToken) {
        log.info("Refreshing access token");
        validateNotBlank(refreshToken, "Refresh token is required");

        try {
            LoginResponse response = keycloakIdentityClient.refreshToken(refreshToken, null);
            log.info("Token refresh successful");
            return response;
        } catch (Exception e) {
            log.error("Token refresh failed", e);
            throw new AuthenticationException("Invalid or expired refresh token", e);
        }
    }

    /**
     * Logout user by invalidating refresh token.
     *
     * @param refreshToken Refresh token to invalidate
     * @throws AuthenticationException if logout fails
     */
    public void logout(String refreshToken) {
        log.info("Logging out user");
        validateNotBlank(refreshToken, "Refresh token is required");

        Client client = ClientBuilder.newClient();
        try {
            String logoutUrl = keycloakProperties.getServerUrl() + "/realms/" + keycloakProperties.getRealm()
                    + "/protocol/openid-connect/logout";

            Form form = new Form()
                    .param("refresh_token", refreshToken)
                    .param("client_id", keycloakProperties.getClientId())
                    .param("client_secret", keycloakProperties.getClientSecret());

            Response response = client.target(logoutUrl).request().post(Entity.form(form));

            if (response.getStatus() == 204 || response.getStatus() == 200) {
                log.info("Logout successful");
            } else {
                log.error("Logout failed with status: {}", response.getStatus());
                throw new AuthenticationException("Logout failed");
            }
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Logout failed", e);
            throw new AuthenticationException("Logout failed", e);
        } finally {
            client.close();
        }
    }

    /**
     * Get user information from token.
     *
     * @param accessToken Valid access token
     * @return Map containing user information
     * @throws AuthenticationException if fetching user info fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getUserInfo(String accessToken) {
        log.info("Fetching user information");
        validateNotBlank(accessToken, "Access token is required");

        Client client = ClientBuilder.newClient();
        try {
            String userInfoUrl = keycloakProperties.getServerUrl() + "/realms/" + keycloakProperties.getRealm()
                    + "/protocol/openid-connect/userinfo";

            String bearerToken = accessToken.startsWith("Bearer ") ? accessToken : "Bearer " + accessToken;

            Response response = client.target(userInfoUrl)
                    .request(MediaType.APPLICATION_JSON)
                    .header("Authorization", bearerToken)
                    .get();

            if (response.getStatus() == 200) {
                Map<String, Object> userInfo = response.readEntity(Map.class);
                log.info("User information retrieved successfully");
                return userInfo;
            } else {
                log.error("Failed to fetch user info with status: {}", response.getStatus());
                throw new AuthenticationException("Failed to fetch user information");
            }
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to fetch user information", e);
            throw new AuthenticationException("Failed to fetch user information", e);
        } finally {
            client.close();
        }
    }

    /**
     * Introspect token to check validity and get claims.
     *
     * @param token Token to introspect
     * @return Map containing token information
     * @throws AuthenticationException if introspection fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> introspectToken(String token) {
        log.info("Introspecting token");
        validateNotBlank(token, "Token is required");

        Client client = ClientBuilder.newClient();
        try {
            String introspectUrl = keycloakProperties.getServerUrl() + "/realms/" + keycloakProperties.getRealm()
                    + "/protocol/openid-connect/token/introspect";

            Form form = new Form()
                    .param("token", token)
                    .param("client_id", keycloakProperties.getClientId())
                    .param("client_secret", keycloakProperties.getClientSecret());

            Response response = client.target(introspectUrl)
                    .request(MediaType.APPLICATION_JSON)
                    .post(Entity.form(form));

            if (response.getStatus() == 200) {
                Map<String, Object> tokenInfo = response.readEntity(Map.class);
                log.info("Token introspection successful");
                return tokenInfo;
            } else {
                log.error("Token introspection failed with status: {}", response.getStatus());
                throw new AuthenticationException("Token introspection failed");
            }
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Token introspection failed", e);
            throw new AuthenticationException("Token introspection failed", e);
        } finally {
            client.close();
        }
    }

    // ==================== USER MANAGEMENT ====================

    /**
     * Get user by email.
     *
     * @param email User's email
     * @return IdpUser containing user details
     * @throws UserNotFoundException if user not found
     */
    public IdpUser getUserByEmail(String email) {
        log.info("Fetching user by email: {}", email);
        validateNotBlank(email, "Email is required");

        try {
            return keycloakIdentityClient.getUser(email);
        } catch (Exception e) {
            log.error("User not found: {}", email, e);
            throw new UserNotFoundException("User not found with email: " + email);
        }
    }

    /**
     * Update user's password.
     *
     * @param email       User's email
     * @param newPassword New password
     * @throws UserNotFoundException   if user not found
     * @throws AuthenticationException if password update fails
     */
    public void updatePassword(String email, String newPassword) {
        log.info("Updating password for user: {}", email);
        validateNotBlank(email, "Email is required");
        validateNotBlank(newPassword, "New password is required");

        try {
            keycloakIdentityClient.setUserPassword(email, newPassword);
            log.info("Password updated successfully for user: {}", email);
        } catch (Exception e) {
            log.error("Password update failed for user: {}", email, e);
            throw new AuthenticationException("Password update failed", e);
        }
    }

    /**
     * Update user's email.
     *
     * @param keycloakUserId User's Keycloak ID
     * @param newEmail       New email address
     * @throws AuthenticationException if email update fails
     */
    public void updateEmail(String keycloakUserId, String newEmail) {
        log.info("Updating email for user ID: {}", keycloakUserId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");
        validateNotBlank(newEmail, "New email is required");

        try {
            keycloakIdentityClient.updateEmail(keycloakUserId, newEmail);
            log.info("Email updated successfully for user ID: {}", keycloakUserId);
        } catch (Exception e) {
            log.error("Email update failed for user ID: {}", keycloakUserId, e);
            throw new AuthenticationException("Email update failed", e);
        }
    }

    /**
     * Set or update user's login PIN.
     *
     * @param keycloakUserId User's Keycloak ID
     * @param loginPin       New login PIN
     * @throws AuthenticationException if PIN update fails
     */
    public void setLoginPin(String keycloakUserId, String loginPin) {
        log.info("Setting login PIN for user ID: {}", keycloakUserId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");
        validateNotBlank(loginPin, "Login PIN is required");

        try {
            keycloakIdentityClient.updateUserLoginPin(keycloakUserId, loginPin);
            log.info("Login PIN set successfully for user ID: {}", keycloakUserId);
        } catch (Exception e) {
            log.error("Login PIN update failed for user ID: {}", keycloakUserId, e);
            throw new AuthenticationException("Login PIN update failed", e);
        }
    }

    /**
     * Set or update user's QWIK PIN.
     *
     * @param keycloakUserId User's Keycloak ID
     * @param qwikPin        New QWIK PIN
     * @throws AuthenticationException if PIN update fails
     */
    public void setQwikPin(String keycloakUserId, String qwikPin) {
        log.info("Setting QWIK PIN for user ID: {}", keycloakUserId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");
        validateNotBlank(qwikPin, "QWIK PIN is required");

        try {
            keycloakIdentityClient.setQwikPin(keycloakUserId, qwikPin);
            log.info("QWIK PIN set successfully for user ID: {}", keycloakUserId);
        } catch (Exception e) {
            log.error("QWIK PIN update failed for user ID: {}", keycloakUserId, e);
            throw new AuthenticationException("QWIK PIN update failed", e);
        }
    }

    /**
     * Update user attributes.
     *
     * @param email      User's email
     * @param attributes Map of attribute names to values
     * @throws AuthenticationException if attribute update fails
     */
    public void updateUserAttributes(String email, Map<String, String> attributes) {
        log.info("Updating attributes for user: {}", email);
        validateNotBlank(email, "Email is required");

        if (attributes == null || attributes.isEmpty()) {
            log.warn("No attributes provided for update");
            return;
        }

        try {
            keycloakIdentityClient.setUserAttributes(email, attributes);
            log.info("Attributes updated successfully for user: {}", email);
        } catch (Exception e) {
            log.error("Attribute update failed for user: {}", email, e);
            throw new AuthenticationException("Attribute update failed", e);
        }
    }

    /**
     * Delete user from Keycloak.
     *
     * @param email User's email
     * @throws UserNotFoundException   if user not found
     * @throws AuthenticationException if deletion fails
     */
    public void deleteUser(String email) {
        log.info("Deleting user: {}", email);
        validateNotBlank(email, "Email is required");

        try {
            keycloakIdentityClient.deleteUser(email);
            log.info("User deleted successfully: {}", email);
        } catch (RuntimeException e) {
            if (e.getMessage() != null && e.getMessage().contains("not found")) {
                throw new UserNotFoundException("User not found: " + email);
            }
            log.error("User deletion failed: {}", email, e);
            throw new AuthenticationException("User deletion failed", e);
        }
    }

    // ==================== GROUP MANAGEMENT ====================

    /**
     * Add user to DSA group.
     *
     * @param keycloakUserId User's Keycloak ID
     * @throws AuthenticationException if operation fails
     */
    public void addUserToDsaGroup(String keycloakUserId) {
        log.info("Adding user to DSA group: {}", keycloakUserId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");

        try {
            Customer customer = new Customer();
            customer.setIdpUsername(keycloakUserId);
            keycloakIdentityClient.joinDsaGroup(customer);
            log.info("User added to DSA group successfully: {}", keycloakUserId);
        } catch (Exception e) {
            log.error("Failed to add user to DSA group: {}", keycloakUserId, e);
            throw new AuthenticationException("Failed to add user to DSA group", e);
        }
    }

    /**
     * Remove user from DSA group.
     *
     * @param keycloakUserId User's Keycloak ID
     * @throws AuthenticationException if operation fails
     */
    public void removeUserFromDsaGroup(String keycloakUserId) {
        log.info("Removing user from DSA group: {}", keycloakUserId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");

        try {
            Customer customer = new Customer();
            customer.setIdpUsername(keycloakUserId);
            keycloakIdentityClient.leaveDsaGroup(customer);
            log.info("User removed from DSA group successfully: {}", keycloakUserId);
        } catch (Exception e) {
            log.error("Failed to remove user from DSA group: {}", keycloakUserId, e);
            throw new AuthenticationException("Failed to remove user from DSA group", e);
        }
    }

    /**
     * Get all DSA group members' customer IDs.
     *
     * @return List of customer IDs in DSA group
     */
    public List<Long> getDsaGroupMembers() {
        log.info("Fetching DSA group members");
        try {
            return keycloakIdentityClient.listAllDsaMembers();
        } catch (Exception e) {
            log.error("Failed to fetch DSA group members", e);
            throw new AuthenticationException("Failed to fetch DSA group members", e);
        }
    }

    // ==================== ROLE MANAGEMENT ====================

    /**
     * Get all realm roles from Keycloak.
     *
     * @return List of RoleRepresentation containing all realm roles
     * @throws AuthenticationException if fetching roles fails
     */
    public List<RoleRepresentation> getRealmRoles() {
        log.info("Fetching all realm roles");
        try {
            List<org.keycloak.representations.idm.RoleRepresentation> keycloakRoles =
                    keycloakIdentityClient.getRealmResource().roles().list();

            return keycloakRoles.stream().map(this::mapToRoleRepresentation).collect(Collectors.toList());
        } catch (Exception e) {
            log.error("Failed to fetch realm roles", e);
            throw new AuthenticationException("Failed to fetch realm roles", e);
        }
    }

    /**
     * Get roles assigned to a specific user.
     *
     * @param keycloakUserId User's Keycloak ID
     * @return List of RoleRepresentation containing user's roles
     * @throws AuthenticationException if fetching user roles fails
     */
    public List<RoleRepresentation> getUserRoles(String keycloakUserId) {
        log.info("Fetching roles for user: {}", keycloakUserId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");

        try {
            UserResource userResource =
                    keycloakIdentityClient.getUsersResource().get(keycloakUserId);
            List<org.keycloak.representations.idm.RoleRepresentation> keycloakRoles =
                    userResource.roles().realmLevel().listEffective();

            return keycloakRoles.stream().map(this::mapToRoleRepresentation).collect(Collectors.toList());
        } catch (Exception e) {
            log.error("Failed to fetch roles for user: {}", keycloakUserId, e);
            throw new AuthenticationException("Failed to fetch user roles", e);
        }
    }

    /**
     * Assign roles to a user.
     *
     * @param keycloakUserId User's Keycloak ID
     * @param roles          List of roles to assign
     * @throws AuthenticationException if role assignment fails
     */
    public void assignRoles(String keycloakUserId, List<RoleRepresentation> roles) {
        log.info("Assigning {} roles to user: {}", roles.size(), keycloakUserId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");

        if (roles == null || roles.isEmpty()) {
            log.warn("No roles provided for assignment");
            return;
        }

        try {
            UserResource userResource =
                    keycloakIdentityClient.getUsersResource().get(keycloakUserId);
            List<org.keycloak.representations.idm.RoleRepresentation> keycloakRoles =
                    roles.stream().map(this::mapToKeycloakRoleRepresentation).collect(Collectors.toList());

            userResource.roles().realmLevel().add(keycloakRoles);
            log.info("Successfully assigned {} roles to user: {}", roles.size(), keycloakUserId);
        } catch (Exception e) {
            log.error("Failed to assign roles to user: {}", keycloakUserId, e);
            throw new AuthenticationException("Failed to assign roles", e);
        }
    }

    /**
     * Assign roles to a user by role names.
     *
     * @param keycloakUserId User's Keycloak ID
     * @param roleNames      List of role names to assign
     * @throws AuthenticationException if role assignment fails
     */
    public void assignRolesByName(String keycloakUserId, List<String> roleNames) {
        log.info("Assigning roles {} to user: {}", roleNames, keycloakUserId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");

        if (roleNames == null || roleNames.isEmpty()) {
            log.warn("No role names provided for assignment");
            return;
        }

        try {
            List<RoleRepresentation> allRoles = getRealmRoles();
            List<RoleRepresentation> rolesToAssign = allRoles.stream()
                    .filter(role -> roleNames.contains(role.getName()))
                    .collect(Collectors.toList());

            if (rolesToAssign.isEmpty()) {
                log.warn("No matching roles found for names: {}", roleNames);
                return;
            }

            assignRoles(keycloakUserId, rolesToAssign);
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to assign roles by name to user: {}", keycloakUserId, e);
            throw new AuthenticationException("Failed to assign roles", e);
        }
    }

    /**
     * Remove roles from a user.
     *
     * @param keycloakUserId User's Keycloak ID
     * @param roles          List of roles to remove
     * @throws AuthenticationException if role removal fails
     */
    public void removeRoles(String keycloakUserId, List<RoleRepresentation> roles) {
        log.info("Removing {} roles from user: {}", roles.size(), keycloakUserId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");

        if (roles == null || roles.isEmpty()) {
            log.warn("No roles provided for removal");
            return;
        }

        try {
            UserResource userResource =
                    keycloakIdentityClient.getUsersResource().get(keycloakUserId);
            List<org.keycloak.representations.idm.RoleRepresentation> keycloakRoles =
                    roles.stream().map(this::mapToKeycloakRoleRepresentation).collect(Collectors.toList());

            userResource.roles().realmLevel().remove(keycloakRoles);
            log.info("Successfully removed {} roles from user: {}", roles.size(), keycloakUserId);
        } catch (Exception e) {
            log.error("Failed to remove roles from user: {}", keycloakUserId, e);
            throw new AuthenticationException("Failed to remove roles", e);
        }
    }

    /**
     * Remove roles from a user by role names.
     *
     * @param keycloakUserId User's Keycloak ID
     * @param roleNames      List of role names to remove
     * @throws AuthenticationException if role removal fails
     */
    public void removeRolesByName(String keycloakUserId, List<String> roleNames) {
        log.info("Removing roles {} from user: {}", roleNames, keycloakUserId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");

        if (roleNames == null || roleNames.isEmpty()) {
            log.warn("No role names provided for removal");
            return;
        }

        try {
            List<RoleRepresentation> userRoles = getUserRoles(keycloakUserId);
            List<RoleRepresentation> rolesToRemove = userRoles.stream()
                    .filter(role -> roleNames.contains(role.getName()))
                    .collect(Collectors.toList());

            if (rolesToRemove.isEmpty()) {
                log.warn("No matching roles found for removal: {}", roleNames);
                return;
            }

            removeRoles(keycloakUserId, rolesToRemove);
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to remove roles by name from user: {}", keycloakUserId, e);
            throw new AuthenticationException("Failed to remove roles", e);
        }
    }

    // ==================== GENERAL GROUP MANAGEMENT ====================

    /**
     * Get all groups in the realm.
     *
     * @return List of GroupRepresentation containing all groups
     * @throws AuthenticationException if fetching groups fails
     */
    public List<GroupRepresentation> getAllGroups() {
        log.info("Fetching all groups");
        try {
            List<org.keycloak.representations.idm.GroupRepresentation> keycloakGroups =
                    keycloakIdentityClient.getRealmResource().groups().groups();

            return keycloakGroups.stream().map(this::mapToGroupRepresentation).collect(Collectors.toList());
        } catch (Exception e) {
            log.error("Failed to fetch groups", e);
            throw new AuthenticationException("Failed to fetch groups", e);
        }
    }

    /**
     * Get groups for a specific user.
     *
     * @param keycloakUserId User's Keycloak ID
     * @return List of GroupRepresentation containing user's groups
     * @throws AuthenticationException if fetching user groups fails
     */
    public List<GroupRepresentation> getUserGroups(String keycloakUserId) {
        log.info("Fetching groups for user: {}", keycloakUserId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");

        try {
            UserResource userResource =
                    keycloakIdentityClient.getUsersResource().get(keycloakUserId);
            List<org.keycloak.representations.idm.GroupRepresentation> keycloakGroups = userResource.groups();

            return keycloakGroups.stream().map(this::mapToGroupRepresentation).collect(Collectors.toList());
        } catch (Exception e) {
            log.error("Failed to fetch groups for user: {}", keycloakUserId, e);
            throw new AuthenticationException("Failed to fetch user groups", e);
        }
    }

    /**
     * Assign user to a group.
     *
     * @param keycloakUserId User's Keycloak ID
     * @param groupId        Group ID to assign user to
     * @throws AuthenticationException if group assignment fails
     */
    public void assignUserToGroup(String keycloakUserId, String groupId) {
        log.info("Assigning user {} to group: {}", keycloakUserId, groupId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");
        validateNotBlank(groupId, "Group ID is required");

        try {
            UserResource userResource =
                    keycloakIdentityClient.getUsersResource().get(keycloakUserId);
            userResource.joinGroup(groupId);
            log.info("Successfully assigned user {} to group: {}", keycloakUserId, groupId);
        } catch (Exception e) {
            log.error("Failed to assign user {} to group: {}", keycloakUserId, groupId, e);
            throw new AuthenticationException("Failed to assign user to group", e);
        }
    }

    /**
     * Assign user to a group by group name.
     *
     * @param keycloakUserId User's Keycloak ID
     * @param groupName      Name of the group to assign user to
     * @throws AuthenticationException if group assignment fails
     */
    public void assignUserToGroupByName(String keycloakUserId, String groupName) {
        log.info("Assigning user {} to group by name: {}", keycloakUserId, groupName);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");
        validateNotBlank(groupName, "Group name is required");

        try {
            List<GroupRepresentation> allGroups = getAllGroups();
            GroupRepresentation targetGroup = allGroups.stream()
                    .filter(group -> groupName.equals(group.getName()))
                    .findFirst()
                    .orElseThrow(() -> new AuthenticationException("Group not found: " + groupName));

            assignUserToGroup(keycloakUserId, targetGroup.getId());
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to assign user {} to group by name: {}", keycloakUserId, groupName, e);
            throw new AuthenticationException("Failed to assign user to group", e);
        }
    }

    /**
     * Remove user from a group.
     *
     * @param keycloakUserId User's Keycloak ID
     * @param groupId        Group ID to remove user from
     * @throws AuthenticationException if group removal fails
     */
    public void removeUserFromGroup(String keycloakUserId, String groupId) {
        log.info("Removing user {} from group: {}", keycloakUserId, groupId);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");
        validateNotBlank(groupId, "Group ID is required");

        try {
            UserResource userResource =
                    keycloakIdentityClient.getUsersResource().get(keycloakUserId);
            userResource.leaveGroup(groupId);
            log.info("Successfully removed user {} from group: {}", keycloakUserId, groupId);
        } catch (Exception e) {
            log.error("Failed to remove user {} from group: {}", keycloakUserId, groupId, e);
            throw new AuthenticationException("Failed to remove user from group", e);
        }
    }

    /**
     * Remove user from a group by group name.
     *
     * @param keycloakUserId User's Keycloak ID
     * @param groupName      Name of the group to remove user from
     * @throws AuthenticationException if group removal fails
     */
    public void removeUserFromGroupByName(String keycloakUserId, String groupName) {
        log.info("Removing user {} from group by name: {}", keycloakUserId, groupName);
        validateNotBlank(keycloakUserId, "Keycloak user ID is required");
        validateNotBlank(groupName, "Group name is required");

        try {
            List<GroupRepresentation> userGroups = getUserGroups(keycloakUserId);
            GroupRepresentation targetGroup = userGroups.stream()
                    .filter(group -> groupName.equals(group.getName()))
                    .findFirst()
                    .orElseThrow(() -> new AuthenticationException("User is not a member of group: " + groupName));

            removeUserFromGroup(keycloakUserId, targetGroup.getId());
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to remove user {} from group by name: {}", keycloakUserId, groupName, e);
            throw new AuthenticationException("Failed to remove user from group", e);
        }
    }

    /**
     * Get group by ID.
     *
     * @param groupId Group ID
     * @return GroupRepresentation containing group details
     * @throws AuthenticationException if fetching group fails
     */
    public GroupRepresentation getGroupById(String groupId) {
        log.info("Fetching group by ID: {}", groupId);
        validateNotBlank(groupId, "Group ID is required");

        try {
            org.keycloak.representations.idm.GroupRepresentation keycloakGroup = keycloakIdentityClient
                    .getRealmResource()
                    .groups()
                    .group(groupId)
                    .toRepresentation();
            return mapToGroupRepresentation(keycloakGroup);
        } catch (Exception e) {
            log.error("Failed to fetch group: {}", groupId, e);
            throw new AuthenticationException("Failed to fetch group", e);
        }
    }

    /**
     * Get group by name.
     *
     * @param groupName Group name
     * @return GroupRepresentation containing group details
     * @throws AuthenticationException if group not found or fetching fails
     */
    public GroupRepresentation getGroupByName(String groupName) {
        log.info("Fetching group by name: {}", groupName);
        validateNotBlank(groupName, "Group name is required");

        try {
            List<GroupRepresentation> allGroups = getAllGroups();
            return allGroups.stream()
                    .filter(group -> groupName.equals(group.getName()))
                    .findFirst()
                    .orElseThrow(() -> new AuthenticationException("Group not found: " + groupName));
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to fetch group by name: {}", groupName, e);
            throw new AuthenticationException("Failed to fetch group", e);
        }
    }

    // ==================== HELPER METHODS ====================

    private void validateNotBlank(String value, String message) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(message);
        }
    }

    private void validateRegistrationRequest(UserRegistrationRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Registration request is required");
        }
        validateNotBlank(request.getEmail(), "Email is required");
        validateNotBlank(request.getPassword(), "Password is required");
        validateNotBlank(request.getUsername(), "Username is required");
    }

    private String generateCustomerId() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    private void updateUserProfile(String keycloakUserId, UserRegistrationRequest request) {
        try {
            UserResource userResource =
                    keycloakIdentityClient.getUsersResource().get(keycloakUserId);
            UserRepresentation user = userResource.toRepresentation();

            if (StringUtils.hasText(request.getFirstName())) {
                user.setFirstName(request.getFirstName());
            }
            if (StringUtils.hasText(request.getLastName())) {
                user.setLastName(request.getLastName());
            }

            userResource.update(user);
        } catch (Exception e) {
            log.warn("Failed to update user profile for: {}", keycloakUserId, e);
        }
    }

    private RoleRepresentation mapToRoleRepresentation(
            org.keycloak.representations.idm.RoleRepresentation keycloakRole) {
        return RoleRepresentation.builder()
                .id(keycloakRole.getId())
                .name(keycloakRole.getName())
                .description(keycloakRole.getDescription())
                .composite(keycloakRole.isComposite())
                .clientRole(keycloakRole.getClientRole())
                .containerId(keycloakRole.getContainerId())
                .build();
    }

    private org.keycloak.representations.idm.RoleRepresentation mapToKeycloakRoleRepresentation(
            RoleRepresentation role) {
        org.keycloak.representations.idm.RoleRepresentation keycloakRole =
                new org.keycloak.representations.idm.RoleRepresentation();
        keycloakRole.setId(role.getId());
        keycloakRole.setName(role.getName());
        keycloakRole.setDescription(role.getDescription());
        keycloakRole.setComposite(role.getComposite() != null && role.getComposite());
        keycloakRole.setClientRole(role.getClientRole() != null && role.getClientRole());
        keycloakRole.setContainerId(role.getContainerId());
        return keycloakRole;
    }

    private GroupRepresentation mapToGroupRepresentation(
            org.keycloak.representations.idm.GroupRepresentation keycloakGroup) {
        List<GroupRepresentation> subGroups = null;
        if (keycloakGroup.getSubGroups() != null) {
            subGroups = keycloakGroup.getSubGroups().stream()
                    .map(this::mapToGroupRepresentation)
                    .collect(Collectors.toList());
        }

        return GroupRepresentation.builder()
                .id(keycloakGroup.getId())
                .name(keycloakGroup.getName())
                .path(keycloakGroup.getPath())
                .subGroups(subGroups)
                .attributes(keycloakGroup.getAttributes())
                .build();
    }
}
