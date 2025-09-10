# Traefik JWT Authentication Middleware

A simple and lightweight Traefik plugin that validates JWT (JSON Web Tokens) against a Redis-based session store. This middleware allows both authenticated and unauthenticated traffic, only validating requests that contain a JWT.

## Key Features

- **Optional Authentication**: Requests without a JWT token are passed directly to the backend without validation.
- **Redis-based Session Revocation**: Validates the token's `jti` (JWT ID) claim against a Redis database to ensure the token is part of an active session.
- **Minimal Configuration**: Designed to be easy to use with minimal required parameters.
- **Built-in Redis Client**: A simple, dependency-free Redis client is included to keep the plugin lightweight.

## Installation

To install the plugin, add the following configuration to your static Traefik configuration file (e.g., `traefik.yml` or `traefik.toml`).

```yaml
# traefik.yml
experimental:
  plugins:
    jwt-auth:
      moduleName: "github.com/your-username/your-repo-name" # Replace with your GitHub repository path
      version: "v1.0.0" # Use a specific version tag
```

## Configuration

The plugin is configured dynamically. Its primary purpose is to connect to your Redis server and retrieve the JWT secret key.

| Parameter        | Type      | Description                                                                 | Default Value        |
|------------------|-----------|-----------------------------------------------------------------------------|----------------------|
| `redisAddresses` | `[]string`| A list of Redis server addresses. Only the first address is used. Can be overridden by `REDIS_ADDR` environment variable. | `["redis:6379"]` |
| `redisPassword`  | `string`  | The password for the Redis server. Can be overridden by `REDIS_PASSWORD` environment variable. | `""`                |
| `redisDB`        | `int`     | The Redis database number to use.                                           | `0`                 |

### Using Environment Variables

For production, it is highly recommended to use environment variables for sensitive data.

- **`JWT_SECRET_VALUE`**: The secret key used to sign and verify the JWT. Must be at least 32 bytes for HS256. This is a required environment variable for production. If not set, a dummy key is used for testing.
- **`REDIS_ADDR`**: Overrides `redisAddresses` in the configuration.
- **`REDIS_PASSWORD`**: Overrides `redisPassword` in the configuration.

### Example Configuration

Here's how to apply the middleware to a router.

```yaml
# In your dynamic configuration file (e.g., dynamic.yml)
http:
  routers:
    my-router:
      rule: "Host(`example.com`)"
      service: "my-service"
      middlewares:
        - "jwt-auth"

  middlewares:
    jwt-auth:
      plugin:
        jwt-auth:
          redisAddresses:
            - "redis-server.my-namespace.svc.cluster.local:6379"
          redisDB: 1
```

## How It Works

This plugin operates based on a simple two-step logic:

1. **Check for JWT**: When a request arrives, the middleware first checks if an `Authorization: Bearer` header is present.
   - **No JWT Found**: If the header is missing, the request is immediately passed to the backend. This allows you to protect specific endpoints while others remain open.
   - **JWT Found**: If a JWT is present, the plugin proceeds to validate it.

2. **JWT Validation**:
   - The JWT signature is verified using the secret key provided via environment variables.
   - The claims `uid` and `jti` are extracted from the token.
   - The plugin queries Redis using the key format `session:{uid}`.
   - The `jti` from the token is compared with the value stored in Redis.
   - If the `jti` values do not match or the session key is not found, the request is rejected with a `401 Unauthorized` status.
   - If the validation succeeds, the request is passed to the next handler.

This approach provides a flexible security layer, allowing you to selectively protect your routes without blocking unauthenticated users.

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue. For code changes, feel free to submit a pull request.

## License

This project is licensed under the MIT License.
