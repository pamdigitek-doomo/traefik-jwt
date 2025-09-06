package jwt_session_checker

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Config struct {
	SecretName      string   `json:"secretName,omitempty"`
	SecretNamespace string   `json:"secretNamespace,omitempty"`
	SecretKey       string   `json:"secretKey,omitempty"`
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

type JWTChecker struct {
	next        http.Handler
	name        string
	config      *Config
	redisClient *redis.Client
	secret      []byte
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Validasi minimal config
	if config.SecretName == "" || config.SecretNamespace == "" || config.SecretKey == "" {
		return nil, fmt.Errorf("secretName, secretNamespace, and secretKey are required")
	}
	if len(config.RedisAddresses) == 0 {
		return nil, fmt.Errorf("redisAddresses is required")
	}

	// Ambil config dari environment kalau ada (override)
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		config.RedisAddresses = []string{addr}
	}
	if pw := os.Getenv("REDIS_PASSWORD"); pw != "" {
		config.RedisPassword = pw
	}

	// Ambil secret dari Kubernetes
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get Kubernetes config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}
	secret, err := clientset.CoreV1().Secrets(config.SecretNamespace).Get(ctx, config.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %v", config.SecretNamespace, config.SecretName, err)
	}
	secretValue, ok := secret.Data[config.SecretKey]
	if !ok {
		return nil, fmt.Errorf("secret key %s not found in secret %s/%s", config.SecretKey, config.SecretNamespace, config.SecretName)
	}

	// Init Redis client
	// Untuk single instance, gunakan address pertama
	redisAddr := config.RedisAddresses[0]

	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	// Test koneksi
	_, err = rdb.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}

	return &JWTChecker{
		next:        next,
		name:        name,
		config:      config,
		redisClient: rdb,
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
		http.Error(rw, "Invalid JWT", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(rw, "Invalid claims", http.StatusUnauthorized)
		return
	}

	uid, uidOk := claims[p.config.UidClaim].(string)
	jti, jtiOk := claims[p.config.JtiClaim].(string)
	if !uidOk || !jtiOk || uid == "" || jti == "" {
		http.Error(rw, "Missing uid or jti", http.StatusUnauthorized)
		return
	}

	// Cek session di Redis
	cachedJTI, err := p.redisClient.Get(context.Background(), "session:"+uid).Result()
	if err != nil {
		if err == redis.Nil {
			http.Error(rw, "Unauthorized: no session", http.StatusUnauthorized)
		} else {
			http.Error(rw, "Unauthorized: redis error", http.StatusUnauthorized)
		}
		return
	}

	if cachedJTI != jti {
		http.Error(rw, "Unauthorized: invalid jti", http.StatusUnauthorized)
		return
	}

	// Lolos → teruskan ke backend
	p.next.ServeHTTP(rw, req)
}
