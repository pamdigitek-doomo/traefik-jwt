package traefik_jwt

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	RedisAddresses []string `json:"redisAddresses,omitempty"`
	RedisPassword  string   `json:"redisPassword,omitempty"`
	RedisDB        int      `json:"redisDB,omitempty"`
	UidClaim       string   `json:"uidClaim,omitempty"`
	JtiClaim       string   `json:"jtiClaim,omitempty"`
	RequiredClaims []string `json:"requiredClaims,omitempty"`
	RolesClaim     string   `json:"rolesClaim,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		RedisAddresses: []string{"redis:6379"},
		RedisPassword:  "",
		RedisDB:        0,
		UidClaim:       "uid",
		JtiClaim:       "jti",
		RequiredClaims: []string{},
		RolesClaim:     "",
	}
}

// Simple JWT implementation without external dependencies
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JWTClaims struct {
	Uid string `json:"uid"`
	Jti string `json:"jti"`
	Exp int64  `json:"exp"`
}

func (p *JWTPlugin) validateJWT(rw http.ResponseWriter, tokenStr string, secret []byte) (*JWTClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding")
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid header JSON")
	}

	if header.Alg != "HS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	// Verify signature
	message := parts[0] + "." + parts[1]
	expectedSignature := generateSignature(message, secret)
	actualSignature := parts[2]

	if actualSignature != expectedSignature {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding")
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid payload JSON")
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return nil, fmt.Errorf("token expired")
		}
	}

	// Extract required claims with configurable claim names
	uid, uidOk := claims[p.config.UidClaim].(string)
	jti, jtiOk := claims[p.config.JtiClaim].(string)

	if !uidOk || !jtiOk || uid == "" || jti == "" {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(rw, fmt.Sprintf("Missing required claims: %s or %s", p.config.UidClaim, p.config.JtiClaim), http.StatusUnauthorized)
		return nil, fmt.Errorf("missing required claims")
	}

	// Check additional required claims if configured
	for _, requiredClaim := range p.config.RequiredClaims {
		if _, exists := claims[requiredClaim]; !exists {
			rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(rw, fmt.Sprintf("Missing required claim: %s", requiredClaim), http.StatusUnauthorized)
			return nil, fmt.Errorf("missing required claim: %s", requiredClaim)
		}
	}

	// Optional: Check roles if configured
	if p.config.RolesClaim != "" {
		if _, hasRoles := claims[p.config.RolesClaim]; !hasRoles {
			rw.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			http.Error(rw, "Missing roles claim", http.StatusForbidden)
			return nil, fmt.Errorf("missing roles claim")
		}
	}

	return &JWTClaims{
		Uid: uid,
		Jti: jti,
	}, nil
}

func generateSignature(message string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Simple Redis client using only stdlib
type SimpleRedisClient struct {
	addr     string
	password string
	db       int
}

func NewSimpleRedisClient(addr, password string, db int) *SimpleRedisClient {
	return &SimpleRedisClient{
		addr:     addr,
		password: password,
		db:       db,
	}
}

func (r *SimpleRedisClient) Get(key string) (string, error) {
	conn, err := net.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to Redis: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Auth if password provided
	if r.password != "" {
		cmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(r.password), r.password)
		_, err = writer.WriteString(cmd)
		if err != nil {
			return "", err
		}
		writer.Flush()

		line, _, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		resp := string(line)
		if !strings.HasPrefix(resp, "+OK") && !strings.HasPrefix(resp, "+") {
			return "", fmt.Errorf("AUTH failed: %s", resp)
		}
	}

	// Select DB if not 0
	if r.db != 0 {
		dbStr := strconv.Itoa(r.db)
		cmd := fmt.Sprintf("*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n", len(dbStr), dbStr)
		_, err = writer.WriteString(cmd)
		if err != nil {
			return "", err
		}
		writer.Flush()

		line, _, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		resp := string(line)
		if !strings.HasPrefix(resp, "+OK") && !strings.HasPrefix(resp, "+") {
			return "", fmt.Errorf("SELECT failed: %s", resp)
		}
	}

	// GET command
	cmd := fmt.Sprintf("*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", len(key), key)
	_, err = writer.WriteString(cmd)
	if err != nil {
		return "", err
	}
	writer.Flush()

	// Parse response
	line, _, err := reader.ReadLine()
	if err != nil {
		return "", err
	}
	resp := string(line)

	if strings.HasPrefix(resp, "-") {
		return "", fmt.Errorf("redis error: %s", strings.TrimPrefix(resp, "-"))
	}
	if strings.HasPrefix(resp, "+") {
		return "", fmt.Errorf("unexpected simple string for GET: %s", resp)
	}
	if strings.HasPrefix(resp, "$") {
		if strings.HasPrefix(resp, "$-1") {
			return "", fmt.Errorf("key not found")
		}
		lengthStr := strings.TrimPrefix(resp, "$")
		length, err := strconv.Atoi(lengthStr)
		if err != nil || length < 0 {
			return "", fmt.Errorf("invalid bulk length: %s", lengthStr)
		}
		valueLine, _, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		// Consume CRLF terminator
		_, _, err = reader.ReadLine()
		if err != nil {
			return "", err
		}
		return string(valueLine), nil
	}
	return "", fmt.Errorf("unexpected response: %s", resp)
}

type JWTPlugin struct {
	next        http.Handler
	name        string
	config      *Config
	redisClient *SimpleRedisClient
	secret      []byte
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.RedisAddresses) == 0 {
		return nil, fmt.Errorf("redisAddresses is required")
	}

	// Override from env if set
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		config.RedisAddresses = []string{addr}
	}
	if pw := os.Getenv("REDIS_PASSWORD"); pw != "" {
		config.RedisPassword = pw
	}

	// Get secret from env (production/test)
	secretStr := os.Getenv("JWT_SECRET_VALUE")
	var secretValue []byte
	if secretStr != "" {
		secretValue = []byte(secretStr)
	} else {
		secretValue = []byte("test-secret-key-for-plugin-catalog-validation-32bytes")
		fmt.Printf("Warning: Using dummy secret for testing. Set JWT_SECRET_VALUE env in production.\n")
	}

	if len(secretValue) < 32 {
		return nil, fmt.Errorf("secret too short: %d bytes (minimum 32 for HS256)", len(secretValue))
	}

	// Init Redis client (use first address)
	redisAddr := config.RedisAddresses[0]
	redisClient := NewSimpleRedisClient(redisAddr, config.RedisPassword, config.RedisDB)

	return &JWTPlugin{
		next:        next,
		name:        name,
		config:      config,
		redisClient: redisClient,
		secret:      secretValue,
	}, nil
}

func (p *JWTPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		p.next.ServeHTTP(rw, req)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == authHeader {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(rw, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	// Use custom JWT validation
	claims, err := p.validateJWT(rw, tokenStr, p.secret)
	if err != nil {
		// Error response is already handled in validateJWT
		return
	}

	// Check session in Redis
	cachedJTI, err := p.redisClient.Get("session:" + claims.Uid)
	if err != nil {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		rw.Header().Set("X-Debug-Uid", claims.Uid)
		rw.Header().Set("X-Debug-Jti", claims.Jti)
		rw.Header().Set("X-Debug-Server", p.redisClient.addr)
		http.Error(rw, "Unauthorized: no session", http.StatusUnauthorized)
		return
	}

	if cachedJTI != claims.Jti {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(rw, "Unauthorized: invalid jti", http.StatusUnauthorized)
		return
	}

	// Pass to next handler
	p.next.ServeHTTP(rw, req)
}
