package com.keycloak.controller;

import com.keycloak.dto.ApiResponse;
import com.keycloak.dto.PasswordResetRequest;
import com.keycloak.dto.RoleAssignmentRequest;
import com.keycloak.dto.UserRegistrationRequest;
import com.keycloak.dto.UserResponse;
import com.keycloak.dto.UserUpdateRequest;
import com.keycloak.dto.keycloakadmin.GroupRepresentation;
import com.keycloak.dto.keycloakadmin.RoleRepresentation;
import com.keycloak.service.UserService;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserResponse>> registerUser(@Valid @RequestBody UserRegistrationRequest request) {
        log.info("Registration request for username: {}", request.getUsername());
        UserResponse response = userService.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(response, "User registered successfully"));
    }

    /**
     * Get all users (paginated)
     * GET /api/users
     */
    @GetMapping
    public ResponseEntity<ApiResponse<Page<UserResponse>>> getAllUsers(Pageable pageable) {
        log.info("Get all users request, page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());
        Page<UserResponse> users = userService.getAllUsers(pageable);
        return ResponseEntity.ok(ApiResponse.success(users, "Users retrieved successfully"));
    }

    /**
     * Get user by ID
     * GET /api/users/{id}
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<UserResponse>> getUserById(@PathVariable Long id) {
        log.info("Get user request for id: {}", id);
        UserResponse response = userService.getUserById(id);
        return ResponseEntity.ok(ApiResponse.success(response, "User retrieved successfully"));
    }

    /**
     * Update user
     * PUT /api/users/{id}
     */
    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<UserResponse>> updateUser(
            @PathVariable Long id, @Valid @RequestBody UserUpdateRequest request) {
        log.info("Update user request for id: {}", id);
        UserResponse response = userService.updateUser(id, request);
        return ResponseEntity.ok(ApiResponse.success(response, "User updated successfully"));
    }

    /**
     * Delete user
     * DELETE /api/users/{id}
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable Long id) {
        log.info("Delete user request for id: {}", id);
        userService.deleteUser(id);
        return ResponseEntity.ok(ApiResponse.success(null, "User deleted successfully"));
    }

    // ==================== Password Management ====================

    /**
     * Reset user password
     * POST /api/users/{id}/reset-password
     */
    @PostMapping("/{id}/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(
            @PathVariable Long id, @Valid @RequestBody PasswordResetRequest request) {
        log.info("Password reset request for user id: {}", id);
        userService.resetPassword(id, request);
        return ResponseEntity.ok(ApiResponse.success(null, "Password reset successfully"));
    }

    // ==================== Role Management ====================

    /**
     * Get all available roles
     * GET /api/users/roles
     */
    @GetMapping("/roles")
    public ResponseEntity<ApiResponse<List<RoleRepresentation>>> getAllRoles() {
        log.info("Get all roles request");
        List<RoleRepresentation> roles = userService.getAllRoles();
        return ResponseEntity.ok(ApiResponse.success(roles, "Roles retrieved successfully"));
    }

    /**
     * Assign roles to user
     * POST /api/users/{id}/roles
     */
    @PostMapping("/{id}/roles")
    public ResponseEntity<ApiResponse<Void>> assignRoles(
            @PathVariable Long id, @Valid @RequestBody RoleAssignmentRequest request) {
        log.info("Assign roles request for user id: {}", id);
        userService.assignRoles(id, request);
        return ResponseEntity.ok(ApiResponse.success(null, "Roles assigned successfully"));
    }

    /**
     * Remove roles from user
     * DELETE /api/users/{id}/roles
     */
    @DeleteMapping("/{id}/roles")
    public ResponseEntity<ApiResponse<Void>> removeRoles(
            @PathVariable Long id, @Valid @RequestBody RoleAssignmentRequest request) {
        log.info("Remove roles request for user id: {}", id);
        userService.removeRoles(id, request);
        return ResponseEntity.ok(ApiResponse.success(null, "Roles removed successfully"));
    }

    // ==================== Group Management ====================

    /**
     * Get all available groups
     * GET /api/users/groups
     */
    @GetMapping("/groups")
    public ResponseEntity<ApiResponse<List<GroupRepresentation>>> getAllGroups() {
        log.info("Get all groups request");
        List<GroupRepresentation> groups = userService.getAllGroups();
        return ResponseEntity.ok(ApiResponse.success(groups, "Groups retrieved successfully"));
    }

    /**
     * Get user groups
     * GET /api/users/{id}/groups
     */
    @GetMapping("/{id}/groups")
    public ResponseEntity<ApiResponse<List<GroupRepresentation>>> getUserGroups(@PathVariable Long id) {
        log.info("Get groups request for user id: {}", id);
        List<GroupRepresentation> groups = userService.getUserGroups(id);
        return ResponseEntity.ok(ApiResponse.success(groups, "User groups retrieved successfully"));
    }

    /**
     * Assign user to group
     * PUT /api/users/{id}/groups/{groupId}
     */
    @PutMapping("/{id}/groups/{groupId}")
    public ResponseEntity<ApiResponse<Void>> assignUserToGroup(@PathVariable Long id, @PathVariable String groupId) {
        log.info("Assign user {} to group {} request", id, groupId);
        userService.assignUserToGroup(id, groupId);
        return ResponseEntity.ok(ApiResponse.success(null, "User assigned to group successfully"));
    }

    /**
     * Remove user from group
     * DELETE /api/users/{id}/groups/{groupId}
     */
    @DeleteMapping("/{id}/groups/{groupId}")
    public ResponseEntity<ApiResponse<Void>> removeUserFromGroup(@PathVariable Long id, @PathVariable String groupId) {
        log.info("Remove user {} from group {} request", id, groupId);
        userService.removeUserFromGroup(id, groupId);
        return ResponseEntity.ok(ApiResponse.success(null, "User removed from group successfully"));
    }
}
