package jwt_session_checker

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	SecretName      string   `json:"secretName,omitempty"`      // Deprecated if using env, but keep for compatibility
	SecretNamespace string   `json:"secretNamespace,omitempty"` // Deprecated
	SecretKey       string   `json:"secretKey,omitempty"`       // Deprecated
	RedisAddresses  []string `json:"redisAddresses,omitempty"`
	RedisPassword   string   `json:"redisPassword,omitempty"`
	RedisDB         int      `json:"redisDB,omitempty"`
	UidClaim        string   `json:"uidClaim,omitempty"`
	JtiClaim        string   `json:"jtiClaim,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		SecretName:      "jwt-secret",
		SecretNamespace: "default",
		SecretKey:       "jwt-secret-key",
		RedisAddresses:  []string{"redis:6379"},
		RedisPassword:   "",
		RedisDB:         0,
		UidClaim:        "uid",
		JtiClaim:        "jti",
	}
}

// Simple Redis client implementation without external dependencies
type SimpleRedisClient struct {
	addr     string
	password string
	db       int
}

func newSimpleRedisClient(addr, password string, db int) *SimpleRedisClient {
	return &SimpleRedisClient{
		addr:     addr,
		password: password,
		db:       db,
	}
}

func (r *SimpleRedisClient) get(key string) (string, error) {
	conn, err := net.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to redis: %v", err)
	}
	defer conn.Close()

	// Set timeout for read/write operations
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Auth if password is provided
	if r.password != "" {
		cmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(r.password), r.password)
		if _, err := writer.WriteString(cmd); err != nil {
			return "", err
		}
		writer.Flush()

		// Read AUTH response
		line, _, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		response := string(line)
		if !strings.HasPrefix(response, "+") {
			return "", fmt.Errorf("auth failed: %s", response)
		}
	}

	// Select database if not 0
	if r.db != 0 {
		dbStr := strconv.Itoa(r.db)
		cmd := fmt.Sprintf("*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n", len(dbStr), dbStr)
		if _, err := writer.WriteString(cmd); err != nil {
			return "", err
		}
		writer.Flush()

		// Read SELECT response
		line, _, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		response := string(line)
		if !strings.HasPrefix(response, "+") {
			return "", fmt.Errorf("select failed: %s", response)
		}
	}

	// Send GET command
	cmd := fmt.Sprintf("*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", len(key), key)
	if _, err := writer.WriteString(cmd); err != nil {
		return "", err
	}
	writer.Flush()

	// Read response
	line, _, err := reader.ReadLine()
	if err != nil {
		return "", err
	}

	response := string(line)

	// Handle error response
	if strings.HasPrefix(response, "-") {
		return "", fmt.Errorf("redis error: %s", strings.TrimPrefix(response, "-"))
	}

	// Handle simple string (e.g., +OK) - though for GET, it should be bulk
	if strings.HasPrefix(response, "+") {
		return "", fmt.Errorf("unexpected simple string for get: %s", response)
	}

	// Handle bulk string or null
	if strings.HasPrefix(response, "$") {
		if strings.HasPrefix(response, "$-1") {
			return "", fmt.Errorf("key not found")
		}

		lengthStr := strings.TrimPrefix(response, "$")
		length, err := strconv.Atoi(lengthStr)
		if err != nil {
			return "", fmt.Errorf("invalid bulk length: %v", err)
		}

		if length < 0 {
			return "", fmt.Errorf("key not found or negative length")
		}

		// Read the actual string value
		valueLine, _, err := reader.ReadLine()
		if err != nil {
			return "", err
		}

		// Read the CRLF terminator (Redis bulk strings end with \r\n after value)
		_, _, err = reader.ReadLine()
		if err != nil {
			return "", err
		}

		return string(valueLine), nil
	}

	return "", fmt.Errorf("unexpected response format: %s", response)
}

type JWTChecker struct {
	next        http.Handler
	name        string
	config      *Config
	redisClient *SimpleRedisClient
	secret      []byte
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Validasi minimal config
	if len(config.RedisAddresses) == 0 {
		return nil, fmt.Errorf("redis addresses is required")
	}

	// Ambil config dari environment kalau ada (override)
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		config.RedisAddresses = []string{addr}
	}
	if pw := os.Getenv("REDIS_PASSWORD"); pw != "" {
		config.RedisPassword = pw
	}

	// Ambil secret dari environment (untuk production/test mode)
	secretStr := os.Getenv("JWT_SECRET_VALUE")
	var secretValue []byte
	if secretStr != "" {
		secretValue = []byte(secretStr)
	} else {
		// Fallback ke dummy untuk test (e.g., Plugin Catalog)
		secretValue = []byte("test-secret-key-for-plugin-catalog-validation-32bytes")
		// Optional: Log warning (gunakan fmt karena no log dep)
		fmt.Printf("warning: using dummy secret for testing. set JWT_SECRET_VALUE env in production.\n")
	}

	// Validasi panjang secret
	if len(secretValue) < 32 {
		return nil, fmt.Errorf("secret too short: %d bytes (minimum 32 for hs256)", len(secretValue))
	}

	// Init simple Redis client
	redisAddr := config.RedisAddresses[0] // TODO: Support multiple addresses with pooling if needed
	redisClient := newSimpleRedisClient(redisAddr, config.RedisPassword, config.RedisDB)

	return &JWTChecker{
		next:        next,
		name:        name,
		config:      config,
		redisClient: redisClient,
		secret:      secretValue,
	}, nil
}

func (p *JWTChecker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		// Tidak ada JWT → teruskan ke backend
		p.next.ServeHTTP(rw, req)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == authHeader {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(rw, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.secret, nil
	})
	if err != nil || !token.Valid {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(rw, "Invalid JWT", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(rw, "Invalid claims", http.StatusUnauthorized)
		return
	}

	uid, uidOk := claims[p.config.UidClaim].(string)
	jti, jtiOk := claims[p.config.JtiClaim].(string)
	if !uidOk || !jtiOk || uid == "" || jti == "" {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(rw, "Missing uid or jti", http.StatusUnauthorized)
		return
	}

	// Cek session di Redis menggunakan simple client
	cachedJTI, err := p.redisClient.get("session:" + uid)
	if err != nil {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(rw, "Unauthorized: no session", http.StatusUnauthorized)
		return
	}

	if cachedJTI != jti {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(rw, "Unauthorized: invalid jti", http.StatusUnauthorized)
		return
	}

	// Lolos → teruskan ke backend
	p.next.ServeHTTP(rw, req)
}
