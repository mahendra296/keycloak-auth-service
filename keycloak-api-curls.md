# Keycloak API cURL Commands for Postman

## Setup Variables
```
KEYCLOAK_URL=http://localhost:8080
REALM=master
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin
CLIENT_ID=admin-cli
CLIENT_SECRET=your-client-secret
```

---

## 1. Authentication APIs

### Get Admin Access Token (Password Grant)
```bash
curl --location '{{KEYCLOAK_URL}}/realms/{{REALM}}/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id={{CLIENT_ID}}' \
--data-urlencode 'username={{ADMIN_USERNAME}}' \
--data-urlencode 'password={{ADMIN_PASSWORD}}' \
--data-urlencode 'grant_type=password'
```

### Get Access Token (Client Credentials)
```bash
curl --location '{{KEYCLOAK_URL}}/realms/{{REALM}}/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id={{CLIENT_ID}}' \
--data-urlencode 'client_secret={{CLIENT_SECRET}}' \
--data-urlencode 'grant_type=client_credentials'
```

### Refresh Access Token
```bash
curl --location '{{KEYCLOAK_URL}}/realms/{{REALM}}/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id={{CLIENT_ID}}' \
--data-urlencode 'client_secret={{CLIENT_SECRET}}' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'refresh_token={{REFRESH_TOKEN}}'
```

### Get User Info
```bash
curl --location '{{KEYCLOAK_URL}}/realms/{{REALM}}/protocol/openid-connect/userinfo' \
--header 'Authorization: Bearer {{ACCESS_TOKEN}}'
```

### Logout
```bash
curl --location '{{KEYCLOAK_URL}}/realms/{{REALM}}/protocol/openid-connect/logout' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id={{CLIENT_ID}}' \
--data-urlencode 'client_secret={{CLIENT_SECRET}}' \
--data-urlencode 'refresh_token={{REFRESH_TOKEN}}'
```

### Introspect Token
```bash
curl --location '{{KEYCLOAK_URL}}/realms/{{REALM}}/protocol/openid-connect/token/introspect' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id={{CLIENT_ID}}' \
--data-urlencode 'client_secret={{CLIENT_SECRET}}' \
--data-urlencode 'token={{ACCESS_TOKEN}}'
```

---

## 2. Realm Management APIs

### Get All Realms
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get Specific Realm
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Create Realm
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "realm": "my-new-realm",
    "enabled": true,
    "displayName": "My New Realm",
    "registrationAllowed": true,
    "loginWithEmailAllowed": true,
    "duplicateEmailsAllowed": false,
    "resetPasswordAllowed": true,
    "editUsernameAllowed": false,
    "bruteForceProtected": true
}'
```

### Update Realm
```bash
curl --location --request PUT '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "realm": "{{REALM}}",
    "enabled": true,
    "displayName": "Updated Realm Name"
}'
```

### Delete Realm
```bash
curl --location --request DELETE '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

---

## 3. User Management APIs

### Get All Users
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get Users with Pagination
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users?first=0&max=20' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Search Users
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users?search=john&first=0&max=20' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get User by ID
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get User by Username
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users?username=john.doe&exact=true' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Create User
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "username": "john.doe",
    "email": "john.doe@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "enabled": true,
    "emailVerified": true,
    "credentials": [{
        "type": "password",
        "value": "Password123!",
        "temporary": false
    }],
    "attributes": {
        "department": ["IT"],
        "employeeId": ["12345"]
    }
}'
```

### Update User
```bash
curl --location --request PUT '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "firstName": "John",
    "lastName": "Doe Updated",
    "email": "john.updated@example.com",
    "enabled": true
}'
```

### Delete User
```bash
curl --location --request DELETE '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Reset User Password
```bash
curl --location --request PUT '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/reset-password' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "type": "password",
    "value": "NewPassword123!",
    "temporary": false
}'
```

### Send Verification Email
```bash
curl --location --request PUT '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/send-verify-email' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Execute Actions Email
```bash
curl --location --request PUT '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/execute-actions-email' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '["UPDATE_PASSWORD", "VERIFY_EMAIL"]'
```

### Get User Sessions
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/sessions' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Logout User (All Sessions)
```bash
curl --location --request POST '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/logout' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get User Count
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/count' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

---

## 4. Client Management APIs

### Get All Clients
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/clients' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get Client by ID
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/clients/{{CLIENT_UUID}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Create Client
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/clients' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "clientId": "my-app",
    "name": "My Application",
    "enabled": true,
    "protocol": "openid-connect",
    "publicClient": false,
    "bearerOnly": false,
    "standardFlowEnabled": true,
    "directAccessGrantsEnabled": true,
    "serviceAccountsEnabled": true,
    "redirectUris": ["http://localhost:3000/*"],
    "webOrigins": ["http://localhost:3000"],
    "attributes": {
        "access.token.lifespan": "1800"
    }
}'
```

### Update Client
```bash
curl --location --request PUT '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/clients/{{CLIENT_UUID}}' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "clientId": "my-app",
    "enabled": true,
    "redirectUris": ["http://localhost:3000/*", "http://localhost:4200/*"]
}'
```

### Delete Client
```bash
curl --location --request DELETE '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/clients/{{CLIENT_UUID}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get Client Secret
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/clients/{{CLIENT_UUID}}/client-secret' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Regenerate Client Secret
```bash
curl --location --request POST '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/clients/{{CLIENT_UUID}}/client-secret' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get Service Account User
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/clients/{{CLIENT_UUID}}/service-account-user' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

---

## 5. Role Management APIs

### Get All Realm Roles
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/roles' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get Realm Role by Name
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/roles/{{ROLE_NAME}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Create Realm Role
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/roles' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "name": "admin",
    "description": "Administrator role",
    "composite": false,
    "clientRole": false
}'
```

### Update Realm Role
```bash
curl --location --request PUT '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/roles/{{ROLE_NAME}}' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "name": "admin",
    "description": "Updated administrator role"
}'
```

### Delete Realm Role
```bash
curl --location --request DELETE '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/roles/{{ROLE_NAME}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get Client Roles
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/clients/{{CLIENT_UUID}}/roles' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Create Client Role
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/clients/{{CLIENT_UUID}}/roles' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "name": "app-admin",
    "description": "Application administrator role"
}'
```

### Assign Realm Roles to User
```bash
curl --location --request POST '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/role-mappings/realm' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '[
    {
        "id": "{{ROLE_ID}}",
        "name": "admin"
    }
]'
```

### Remove Realm Roles from User
```bash
curl --location --request DELETE '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/role-mappings/realm' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '[
    {
        "id": "{{ROLE_ID}}",
        "name": "admin"
    }
]'
```

### Get User Realm Role Mappings
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/role-mappings/realm' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Assign Client Roles to User
```bash
curl --location --request POST '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/role-mappings/clients/{{CLIENT_UUID}}' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '[
    {
        "id": "{{ROLE_ID}}",
        "name": "app-admin"
    }
]'
```

### Get User Client Role Mappings
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/role-mappings/clients/{{CLIENT_UUID}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

---

## 6. Group Management APIs

### Get All Groups
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/groups' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get Group by ID
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/groups/{{GROUP_ID}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Create Group
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/groups' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "name": "developers",
    "attributes": {
        "department": ["Engineering"]
    }
}'
```

### Update Group
```bash
curl --location --request PUT '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/groups/{{GROUP_ID}}' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "name": "senior-developers",
    "attributes": {
        "department": ["Engineering"],
        "level": ["Senior"]
    }
}'
```

### Delete Group
```bash
curl --location --request DELETE '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/groups/{{GROUP_ID}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Add User to Group
```bash
curl --location --request PUT '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/groups/{{GROUP_ID}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Remove User from Group
```bash
curl --location --request DELETE '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/groups/{{GROUP_ID}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get User Groups
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/users/{{USER_ID}}/groups' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get Group Members
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/groups/{{GROUP_ID}}/members' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

---

## 7. Identity Provider APIs

### Get All Identity Providers
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/identity-provider/instances' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Create Identity Provider (Google)
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/identity-provider/instances' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "alias": "google",
    "providerId": "google",
    "enabled": true,
    "config": {
        "clientId": "your-google-client-id",
        "clientSecret": "your-google-client-secret",
        "defaultScope": "openid profile email"
    }
}'
```

### Update Identity Provider
```bash
curl --location --request PUT '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/identity-provider/instances/{{IDP_ALIAS}}' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "alias": "google",
    "enabled": true,
    "config": {
        "clientId": "updated-client-id",
        "clientSecret": "updated-client-secret"
    }
}'
```

### Delete Identity Provider
```bash
curl --location --request DELETE '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/identity-provider/instances/{{IDP_ALIAS}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

---

## 8. Session Management APIs

### Get Active Sessions
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/client-session-stats' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Delete Session
```bash
curl --location --request DELETE '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/sessions/{{SESSION_ID}}' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

---

## 9. Events APIs

### Get Events
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/events?type=LOGIN&first=0&max=100' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Get Admin Events
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/admin-events?first=0&max=100' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Clear Events
```bash
curl --location --request DELETE '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/events' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

---

## 10. Client Scope APIs

### Get All Client Scopes
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/client-scopes' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}'
```

### Create Client Scope
```bash
curl --location '{{KEYCLOAK_URL}}/admin/realms/{{REALM}}/client-scopes' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ADMIN_ACCESS_TOKEN}}' \
--data '{
    "name": "custom-scope",
    "description": "Custom scope for specific claims",
    "protocol": "openid-connect",
    "attributes": {
        "include.in.token.scope": "true"
    }
}'
```

---

## Notes for Postman Setup:

1. **Create Environment Variables:**
   - `KEYCLOAK_URL`: Your Keycloak server URL
   - `REALM`: Realm name (usually 'master' for admin operations)
   - `ADMIN_USERNAME`: Admin username
   - `ADMIN_PASSWORD`: Admin password
   - `CLIENT_ID`: Client ID (e.g., 'admin-cli')
   - `CLIENT_SECRET`: Client secret (if applicable)
   - `ADMIN_ACCESS_TOKEN`: Store token from authentication
   - `USER_ID`: User UUID
   - `CLIENT_UUID`: Client UUID
   - `GROUP_ID`: Group UUID
   - `ROLE_ID`: Role ID

2. **Pre-request Script for Auto Token Refresh:**
```javascript
// Add this to collection pre-request script
const tokenUrl = pm.environment.get("KEYCLOAK_URL") + "/realms/" + pm.environment.get("REALM") + "/protocol/openid-connect/token";

pm.sendRequest({
    url: tokenUrl,
    method: 'POST',
    header: 'Content-Type: application/x-www-form-urlencoded',
    body: {
        mode: 'urlencoded',
        urlencoded: [
            {key: "client_id", value: pm.environment.get("CLIENT_ID")},
            {key: "username", value: pm.environment.get("ADMIN_USERNAME")},
            {key: "password", value: pm.environment.get("ADMIN_PASSWORD")},
            {key: "grant_type", value: "password"}
        ]
    }
}, function (err, res) {
    if (!err) {
        pm.environment.set("ADMIN_ACCESS_TOKEN", res.json().access_token);
    }
});
```

3. **Test Script to Extract IDs:**
```javascript
// Add to requests that create resources
if (pm.response.code === 201) {
    const location = pm.response.headers.get("Location");
    const id = location.split("/").pop();
    pm.environment.set("LAST_CREATED_ID", id);
}
```

---

## Common Response Codes:
- `200 OK`: Successful GET/PUT
- `201 Created`: Resource created successfully (check Location header for ID)
- `204 No Content`: Successful DELETE
- `401 Unauthorized`: Invalid or expired token
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource already exists
