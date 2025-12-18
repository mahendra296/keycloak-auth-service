# Keycloak Authentication Service

A Spring Boot microservice that provides authentication using Keycloak with support for password-based, OTP-based, PIN-based, and passwordless login.

## Features

- **Password Authentication**: Traditional username/password login via Keycloak
- **PIN Authentication**: Quick login using a numeric PIN
- **OTP Authentication**: One-Time Password based login with database management
- **Passwordless Authentication**: Phone-based login with OTP and biometric support
- **Token Management**: Access token refresh, validation, and introspection
- **User Management**: Full CRUD operations with Keycloak integration
- **Role Management**: Assign and remove roles from users
- **Group Management**: Manage user group memberships
- **Feign Client**: All Keycloak API calls made through Spring Cloud OpenFeign
- **Security**: Stateless JWT-based authentication with Spring Security

## Technologies

- Java 17
- Spring Boot 3.2.0
- Spring Security
- Spring Data JPA
- Spring Cloud OpenFeign
- Keycloak 23.0.3
- H2/MySQL Database
- Lombok
- Maven

## Prerequisites

1. Java 17 or higher
2. Maven 3.6+
3. Keycloak Server (v23.0.3 or compatible)
4. MySQL (optional, H2 is default)

## Keycloak Setup

### 1. Install and Start Keycloak

```bash
# Download Keycloak
wget https://github.com/keycloak/keycloak/releases/download/23.0.3/keycloak-23.0.3.zip
unzip keycloak-23.0.3.zip
cd keycloak-23.0.3

# Start Keycloak
bin/kc.sh start-dev --http-port=8180
```

### 2. Create Realm and Client

1. Access Keycloak Admin Console: `http://localhost:8180`
2. Login with admin credentials
3. Create a new realm (e.g., "your-realm")
4. Create a client:
    - Client ID: `your-client-id`
    - Client Protocol: `openid-connect`
    - Access Type: `confidential`
    - Valid Redirect URIs: `*`
    - Direct Access Grants Enabled: `ON`
5. Go to Credentials tab and copy the client secret
6. Create test users in the realm

### 3. Update Application Configuration

Update `src/main/resources/application.yml`:

```yaml
keycloak:
  realm: your-realm
  auth-server-url: http://localhost:8180/auth
  resource: your-client-id
  credentials:
    secret: your-client-secret

keycloak-admin:
  server-url: http://localhost:8180/auth
  realm: your-realm
  client-id: your-client-id
  client-secret: your-client-secret
```

## Build and Run

### Using Maven

```bash
# Build the project
mvn clean install

# Run the application
mvn spring-boot:run
```

### Using JAR

```bash
# Build JAR
mvn clean package

# Run JAR
java -jar target/keycloak-auth-service-1.0.0.jar
```

The application will start on `http://localhost:8080`

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/health` | Health check |
| POST | `/api/auth/login` | Login with username/password |
| POST | `/api/auth/login/pin` | Login with PIN |
| POST | `/api/auth/otp/send` | Send OTP to user |
| POST | `/api/auth/otp/send/{username}` | Send OTP (simple) |
| POST | `/api/auth/otp/validate` | Validate OTP only |
| POST | `/api/auth/otp/validate-and-login` | Validate OTP and get tokens |
| POST | `/api/auth/otp/verify` | Verify OTP and login (legacy) |
| POST | `/api/auth/passwordless/initiate` | Initiate passwordless login |
| POST | `/api/auth/passwordless/validate` | Validate passwordless login |
| POST | `/api/auth/refresh` | Refresh access token |
| GET | `/api/auth/validate` | Validate token |
| GET | `/api/auth/userinfo` | Get user information |
| POST | `/api/auth/logout` | Logout user |

### User Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/users/register` | Register new user |
| GET | `/api/users` | Get all users (paginated) |
| GET | `/api/users/{id}` | Get user by ID |
| PUT | `/api/users/{id}` | Update user |
| DELETE | `/api/users/{id}` | Delete user |
| POST | `/api/users/{id}/reset-password` | Reset user password |
| GET | `/api/users/roles` | Get all available roles |
| POST | `/api/users/{id}/roles` | Assign roles to user |
| DELETE | `/api/users/{id}/roles` | Remove roles from user |
| GET | `/api/users/groups` | Get all available groups |
| GET | `/api/users/{id}/groups` | Get user groups |
| PUT | `/api/users/{id}/groups/{groupId}` | Assign user to group |
| DELETE | `/api/users/{id}/groups/{groupId}` | Remove user from group |

## API Examples

### 1. Health Check
```http
GET /api/auth/health
```

### 2. Login with Password
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "testuser",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI...",
    "expires_in": 300,
    "refresh_expires_in": 1800,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI...",
    "token_type": "Bearer"
  },
  "timestamp": "2024-12-17T10:30:00"
}
```

### 3. Login with PIN
```http
POST /api/auth/login/pin?username=testuser&pin=123456
```

### 4. Send OTP
```http
POST /api/auth/otp/send
Content-Type: application/json

{
  "username": "testuser"
}
```

### 5. Validate OTP and Login
```http
POST /api/auth/otp/validate-and-login
Content-Type: application/json

{
  "username": "testuser",
  "otp_code": "123456"
}
```

### 6. Initiate Passwordless Login
```http
POST /api/auth/passwordless/initiate?username=testuser
```

**Response:**
```json
{
  "success": true,
  "message": "OTP sent successfully",
  "data": {
    "sessionCode": "abc123...",
    "expiresIn": 300
  }
}
```

### 7. Validate Passwordless Login
```http
POST /api/auth/passwordless/validate
Content-Type: application/json

{
  "phoneNumber": "+1234567890",
  "sessionCode": "abc123...",
  "otp": "123456",
  "isBiometricEnabled": false
}
```

### 8. Refresh Token
```http
POST /api/auth/refresh?refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI...
```

### 9. Validate Token
```http
GET /api/auth/validate
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI...
```

### 10. Get User Info
```http
GET /api/auth/userinfo
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI...
```

### 11. Logout
```http
POST /api/auth/logout?refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI...
```

### 12. Register User
```http
POST /api/users/register
Content-Type: application/json

{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "Password123!",
  "firstName": "John",
  "lastName": "Doe",
  "phone": "+1234567890",
  "address": "123 Main St",
  "city": "New York",
  "country": "USA",
  "postalCode": "10001"
}
```

## Postman Collection

A complete Postman collection is included for testing all API endpoints.

### Import Instructions

1. Open Postman
2. Click **Import** button
3. Select the file: `postman.json`
4. The collection "Keycloak Auth Service" will be imported

### Collection Structure

- **Health** - Health check endpoint
- **Authentication - Password** - Password and PIN login
- **Authentication - OTP** - OTP send, validate, and login
- **Authentication - Passwordless** - Passwordless login flow
- **Token Management** - Refresh, validate, userinfo, logout
- **User Management** - CRUD operations for users
- **Role Management** - Role assignment and removal
- **Group Management** - Group membership management

### Environment Variables

The collection uses the following variables (pre-configured):

| Variable | Default Value | Description |
|----------|---------------|-------------|
| `baseUrl` | `http://localhost:8080/api` | API base URL |
| `accessToken` | (auto-populated) | JWT access token |
| `refreshToken` | (auto-populated) | JWT refresh token |
| `userId` | `1` | User ID for user operations |
| `groupId` | | Group ID for group operations |
| `sessionCode` | (auto-populated) | Passwordless session code |

### Auto-Token Management

The collection automatically saves tokens to environment variables when you:
- Login with password/PIN
- Login with OTP
- Complete passwordless login
- Refresh tokens

Tokens are automatically cleared on logout.

## Database Schema

### OTP Records Table

```sql
CREATE TABLE otp_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    otp_code VARCHAR(10) NOT NULL,
    valid_until TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP
);
```

## OTP Configuration

Configure OTP settings in `application.yml`:

```yaml
otp:
  expiry-minutes: 5      # OTP validity duration
  length: 6              # OTP code length
  max-attempts: 3        # Maximum verification attempts
```

## Testing with cURL

### Password Login
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

### PIN Login
```bash
curl -X POST "http://localhost:8080/api/auth/login/pin?username=testuser&pin=123456"
```

### Send OTP
```bash
curl -X POST http://localhost:8080/api/auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser"
  }'
```

### Validate OTP and Login
```bash
curl -X POST http://localhost:8080/api/auth/otp/validate-and-login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "otp_code": "123456"
  }'
```

### Initiate Passwordless Login
```bash
curl -X POST "http://localhost:8080/api/auth/passwordless/initiate?username=testuser"
```

### Validate Passwordless Login
```bash
curl -X POST http://localhost:8080/api/auth/passwordless/validate \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "+1234567890",
    "sessionCode": "YOUR_SESSION_CODE",
    "otp": "123456",
    "isBiometricEnabled": false
  }'
```

### Refresh Token
```bash
curl -X POST "http://localhost:8080/api/auth/refresh?refresh_token=YOUR_REFRESH_TOKEN"
```

### Validate Token
```bash
curl -X GET http://localhost:8080/api/auth/validate \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Get User Info
```bash
curl -X GET http://localhost:8080/api/auth/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Register User
```bash
curl -X POST http://localhost:8080/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "Password123!",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

## Database Access

### H2 Console (Development)

Access H2 console at: `http://localhost:8080/api/h2-console`

- JDBC URL: `jdbc:h2:mem:authdb`
- Username: `sa`
- Password: `password`

### Switch to MySQL

Update `application.yml`:

```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/auth_db
    driver-class-name: com.mysql.cj.jdbc.Driver
    username: root
    password: root
  jpa:
    properties:
      hibernate:
        dialect: org.hibernate.dialect.MySQL8Dialect
```

## Project Structure

```
keycloak-auth-service/
├── src/
│   ├── main/
│   │   ├── java/com/keycloak/
│   │   │   ├── client/              # Feign clients
│   │   │   ├── config/              # Configuration classes
│   │   │   ├── controller/          # REST controllers
│   │   │   │   ├── AuthController.java
│   │   │   │   └── UserController.java
│   │   │   ├── dto/                 # Data transfer objects
│   │   │   ├── entity/              # JPA entities
│   │   │   ├── exception/           # Exception handling
│   │   │   ├── repository/          # Data repositories
│   │   │   ├── service/             # Business logic
│   │   │   └── KeycloakAuthServiceApplication.java
│   │   └── resources/
│   │       └── application.yml
│   └── test/
├── postman.json                     # Postman collection
├── pom.xml
└── README.md
```

## Security Considerations

1. **OTP Delivery**: In production, integrate with email/SMS service (AWS SNS, Twilio, SendGrid)
2. **HTTPS**: Always use HTTPS in production
3. **Rate Limiting**: Implement rate limiting for OTP generation
4. **Secret Management**: Use environment variables or secret managers for sensitive data
5. **Token Storage**: Store tokens securely on the client side
6. **OTP Cleanup**: Scheduled task runs hourly to clean expired OTPs
7. **PIN Security**: Store PINs hashed, implement lockout after failed attempts

## Troubleshooting

### Issue: Connection refused to Keycloak
- Ensure Keycloak is running on port 8180
- Check `auth-server-url` in application.yml

### Issue: Invalid client credentials
- Verify client-id and client-secret in application.yml
- Ensure client is configured correctly in Keycloak

### Issue: OTP not working
- Check database connection
- Verify OTP is not expired (check `valid_until` column)
- Ensure attempts < max_attempts

### Issue: Token validation fails
- Check if token is expired
- Verify the token was issued by the correct Keycloak realm
- Ensure the Authorization header format is "Bearer {token}"

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License.

## Contact

For questions or support, please open an issue in the repository.
