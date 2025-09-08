package jwt

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

// Simple Redis client using only stdlib (no redigo dependency)
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

	// Check session in Redis
	cachedJTI, err := p.redisClient.Get("session:" + uid)
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

	// Pass to next handler
	p.next.ServeHTTP(rw, req)
}
