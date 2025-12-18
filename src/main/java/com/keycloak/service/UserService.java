package com.keycloak.service;

import com.keycloak.dto.PasswordResetRequest;
import com.keycloak.dto.RoleAssignmentRequest;
import com.keycloak.dto.UserRegistrationRequest;
import com.keycloak.dto.UserResponse;
import com.keycloak.dto.UserUpdateRequest;
import com.keycloak.dto.keycloakadmin.GroupRepresentation;
import com.keycloak.dto.keycloakadmin.RoleRepresentation;
import com.keycloak.entity.User;
import com.keycloak.entity.User.SyncStatus;
import com.keycloak.entity.User.UserStatus;
import com.keycloak.exceptions.UserAlreadyExistsException;
import com.keycloak.exceptions.UserNotFoundException;
import com.keycloak.exceptions.UserSyncException;
import com.keycloak.repository.UserRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final KeycloakService keycloakUserService;

    @Transactional
    public UserResponse registerUser(UserRegistrationRequest request) {
        log.info("Registering new user: {}", request.getUsername());

        // Validate user doesn't exist locally
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Email already exists");
        }
        String keycloakUserId;

        try {
            keycloakUserId = keycloakUserService.registerUser(request).getUserId();
        } catch (UserAlreadyExistsException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to create user in Keycloak", e);
            throw new UserSyncException("Failed to create user in Keycloak", e);
        }

        // Step 2: Save to local database
        User localUser = buildLocalUser(request, keycloakUserId);

        try {
            User savedUser = userRepository.save(localUser);
            log.info("User registered successfully: {}", savedUser.getUsername());
            return UserResponse.fromEntity(savedUser);
        } catch (Exception e) {
            log.error("Failed to save user locally, attempting compensation", e);
            try {
                keycloakUserService.deleteUser(keycloakUserId);
                log.info("Compensation successful: deleted user from Keycloak");
            } catch (Exception compensationError) {
                log.error(
                        "Compensation failed: user {} exists in Keycloak but not in local DB",
                        keycloakUserId,
                        compensationError);
            }
            throw new UserSyncException("Failed to complete user registration", e);
        }
    }

    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));
        return UserResponse.fromEntity(user);
    }

    @Transactional
    public UserResponse updateUser(Long id, UserUpdateRequest request) {
        User user = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));

        try {
            // keycloakUserService.updateUser(user.getKeycloakUserId(), request);
        } catch (Exception e) {
            log.error("Failed to update user in Keycloak", e);
            throw new UserSyncException("Failed to update user in Keycloak", e);
        }

        // Update local database
        updateLocalUserFields(user, request);
        User savedUser = userRepository.save(user);

        return UserResponse.fromEntity(savedUser);
    }

    @Transactional
    public void deleteUser(Long id) {
        User user = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));

        // Delete from Keycloak first
        try {
            keycloakUserService.deleteUser(user.getKeycloakUserId());
        } catch (UserNotFoundException e) {
            log.warn("User not found in Keycloak, proceeding with local deletion");
        } catch (Exception e) {
            log.error("Failed to delete user from Keycloak", e);
            throw new UserSyncException("Failed to delete user from Keycloak", e);
        }

        // Delete from local database
        userRepository.delete(user);
        log.info("User deleted: {}", user.getUsername());
    }

    public void resetPassword(Long id, PasswordResetRequest request) {
        User user = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));

        /*keycloakUserService.resetPassword(
                user.getKeycloakUserId(),
                request.getNewPassword(),
                request.getTemporary() != null && request.getTemporary());
        log.info("Password reset for user: {}", user.getUsername());*/
    }

    public Page<UserResponse> getAllUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(UserResponse::fromEntity);
    }

    public void assignRoles(Long id, RoleAssignmentRequest request) {
        User user = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));

        List<RoleRepresentation> allRoles = keycloakUserService.getRealmRoles();
        List<RoleRepresentation> rolesToAssign = allRoles.stream()
                .filter(role -> request.getRoleNames().contains(role.getName()))
                .toList();

        if (rolesToAssign.isEmpty()) {
            log.warn("No matching roles found for assignment");
            return;
        }

        keycloakUserService.assignRoles(user.getKeycloakUserId(), rolesToAssign);
        log.info("Assigned {} roles to user: {}", rolesToAssign.size(), user.getUsername());
    }

    public void removeRoles(Long id, RoleAssignmentRequest request) {
        User user = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));

        List<RoleRepresentation> userRoles = keycloakUserService.getUserRoles(user.getKeycloakUserId());
        List<RoleRepresentation> rolesToRemove = userRoles.stream()
                .filter(role -> request.getRoleNames().contains(role.getName()))
                .toList();

        if (rolesToRemove.isEmpty()) {
            log.warn("No matching roles found for removal");
            return;
        }

        keycloakUserService.removeRoles(user.getKeycloakUserId(), rolesToRemove);
        log.info("Removed {} roles from user: {}", rolesToRemove.size(), user.getUsername());
    }

    // Group Management
    public List<GroupRepresentation> getUserGroups(Long id) {
        User user = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));
        return keycloakUserService.getUserGroups(user.getKeycloakUserId());
    }

    public void assignUserToGroup(Long id, String groupId) {
        User user = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));
        keycloakUserService.assignUserToGroup(user.getKeycloakUserId(), groupId);
        log.info("Assigned user {} to group {}", user.getUsername(), groupId);
    }

    public void removeUserFromGroup(Long id, String groupId) {
        User user = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));
        keycloakUserService.removeUserFromGroup(user.getKeycloakUserId(), groupId);
        log.info("Removed user {} from group {}", user.getUsername(), groupId);
    }

    public List<GroupRepresentation> getAllGroups() {
        return keycloakUserService.getAllGroups();
    }

    public List<RoleRepresentation> getAllRoles() {
        return keycloakUserService.getRealmRoles();
    }

    private User buildLocalUser(UserRegistrationRequest request, String keycloakUserId) {
        return User.builder()
                .keycloakUserId(keycloakUserId)
                .username(request.getUsername())
                .email(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phone(request.getPhone())
                .address(request.getAddress())
                .city(request.getCity())
                .country(request.getCountry())
                .postalCode(request.getPostalCode())
                .status(UserStatus.ACTIVE)
                .syncStatus(SyncStatus.SYNCED)
                .build();
    }

    private void updateLocalUserFields(User user, UserUpdateRequest request) {
        if (request.getFirstName() != null) user.setFirstName(request.getFirstName());
        if (request.getLastName() != null) user.setLastName(request.getLastName());
        if (request.getPhone() != null) user.setPhone(request.getPhone());
        if (request.getAddress() != null) user.setAddress(request.getAddress());
        if (request.getCity() != null) user.setCity(request.getCity());
        if (request.getCountry() != null) user.setCountry(request.getCountry());
        if (request.getPostalCode() != null) user.setPostalCode(request.getPostalCode());
    }
}
