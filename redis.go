package traefik_jwt

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Improved Redis client with better error handling and timeout management
type ImprovedRedisClient struct {
	addr     string
	password string
	db       int
	timeout  time.Duration
}

func NewImprovedRedisClient(addr, password string, db int) *ImprovedRedisClient {
	return &ImprovedRedisClient{
		addr:     addr,
		password: password,
		db:       db,
		timeout:  15 * time.Second, // Increased timeout from 5s to 15s
	}
}

func (r *ImprovedRedisClient) Get(key string) (string, error) {
	conn, err := net.DialTimeout("tcp", r.addr, r.timeout)
	if err != nil {
		return "", fmt.Errorf("connection failed to %s: %v", r.addr, err)
	}
	defer conn.Close()

	// Set read/write deadline
	conn.SetDeadline(time.Now().Add(r.timeout))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Auth if password provided
	if r.password != "" {
		if err := r.authenticate(reader, writer); err != nil {
			return "", fmt.Errorf("auth error: %v", err)
		}
	}

	// Select DB if not 0
	if r.db != 0 {
		if err := r.selectDatabase(reader, writer); err != nil {
			return "", fmt.Errorf("select db error: %v", err)
		}
	}

	// Execute GET command
	return r.executeGet(reader, writer, key)
}

func (r *ImprovedRedisClient) authenticate(reader *bufio.Reader, writer *bufio.Writer) error {
	cmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(r.password), r.password)

	if _, err := writer.WriteString(cmd); err != nil {
		return fmt.Errorf("write auth command failed: %v", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush auth command failed: %v", err)
	}

	// Read AUTH response
	line, _, err := reader.ReadLine()
	if err != nil {
		return fmt.Errorf("read auth response failed: %v", err)
	}

	resp := string(line)
	if !strings.HasPrefix(resp, "+OK") && !strings.HasPrefix(resp, "+") {
		return fmt.Errorf("auth rejected: %s", resp)
	}

	return nil
}

func (r *ImprovedRedisClient) selectDatabase(reader *bufio.Reader, writer *bufio.Writer) error {
	dbStr := strconv.Itoa(r.db)
	cmd := fmt.Sprintf("*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n", len(dbStr), dbStr)

	if _, err := writer.WriteString(cmd); err != nil {
		return fmt.Errorf("write select command failed: %v", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush select command failed: %v", err)
	}

	// Read SELECT response
	line, _, err := reader.ReadLine()
	if err != nil {
		return fmt.Errorf("read select response failed: %v", err)
	}

	resp := string(line)
	if !strings.HasPrefix(resp, "+OK") && !strings.HasPrefix(resp, "+") {
		return fmt.Errorf("select rejected: %s", resp)
	}

	return nil
}

func (r *ImprovedRedisClient) executeGet(reader *bufio.Reader, writer *bufio.Writer, key string) (string, error) {
	// Send GET command
	cmd := fmt.Sprintf("*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", len(key), key)

	if _, err := writer.WriteString(cmd); err != nil {
		return "", fmt.Errorf("write get command failed: %v", err)
	}
	if err := writer.Flush(); err != nil {
		return "", fmt.Errorf("flush get command failed: %v", err)
	}

	// Parse GET response
	return r.parseGetResponse(reader, key)
}

func (r *ImprovedRedisClient) parseGetResponse(reader *bufio.Reader, key string) (string, error) {
	line, _, err := reader.ReadLine()
	if err != nil {
		return "", fmt.Errorf("read get response failed: %v", err)
	}

	resp := string(line)

	// Handle error response
	if strings.HasPrefix(resp, "-") {
		return "", fmt.Errorf("redis error: %s", strings.TrimPrefix(resp, "-"))
	}

	// Handle unexpected simple string
	if strings.HasPrefix(resp, "+") {
		return "", fmt.Errorf("unexpected simple string response: %s", resp)
	}

	// Handle bulk string response
	if strings.HasPrefix(resp, "$") {
		// Handle null bulk string (key not found)
		if resp == "$-1" {
			return "", fmt.Errorf("key not found: %s", key)
		}

		// Parse bulk string length
		lengthStr := strings.TrimPrefix(resp, "$")
		length, err := strconv.Atoi(lengthStr)
		if err != nil {
			return "", fmt.Errorf("invalid bulk string length: %s", lengthStr)
		}
		if length < 0 {
			return "", fmt.Errorf("negative bulk string length: %d", length)
		}

		// Read the actual data
		data := make([]byte, length)
		totalRead := 0

		// Read data with proper handling of partial reads
		for totalRead < length {
			n, err := reader.Read(data[totalRead:])
			if err != nil {
				return "", fmt.Errorf("failed to read bulk string data: %v (read %d/%d bytes)", err, totalRead, length)
			}
			totalRead += n
		}

		// Consume the trailing CRLF
		reader.ReadLine()

		return string(data), nil
	}

	return "", fmt.Errorf("unexpected response format: %s", resp)
}

// Test connectivity method
func (r *ImprovedRedisClient) Ping() error {
	conn, err := net.DialTimeout("tcp", r.addr, r.timeout)
	if err != nil {
		return fmt.Errorf("ping connection failed to %s: %v", r.addr, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(r.timeout))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Auth if needed
	if r.password != "" {
		if err := r.authenticate(reader, writer); err != nil {
			return fmt.Errorf("ping auth failed: %v", err)
		}
	}

	// Send PING command
	cmd := "*1\r\n$4\r\nPING\r\n"
	if _, err := writer.WriteString(cmd); err != nil {
		return fmt.Errorf("ping write failed: %v", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("ping flush failed: %v", err)
	}

	// Read PING response
	line, _, err := reader.ReadLine()
	if err != nil {
		return fmt.Errorf("ping read failed: %v", err)
	}

	resp := string(line)
	if resp != "+PONG" {
		return fmt.Errorf("unexpected ping response: %s", resp)
	}

	return nil
}
