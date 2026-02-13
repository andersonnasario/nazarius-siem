package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/sts"
)

// AWSCredentials representa credenciais temporárias da AWS
type AWSCredentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	Expiration      time.Time `json:"expiration"`
	Region          string    `json:"region"`
}

// AccountConnection representa a conexão com uma conta AWS
type AccountConnection struct {
	ID           string          `json:"id"`
	AccountID    string          `json:"account_id"`
	AccountName  string          `json:"account_name"`
	RoleARN      string          `json:"role_arn"`
	ExternalID   string          `json:"external_id,omitempty"`
	Region       string          `json:"region"`
	Credentials  *AWSCredentials `json:"credentials,omitempty"`
	LastRefresh  time.Time       `json:"last_refresh"`
	LastSync     time.Time       `json:"last_sync"`
	Status       string          `json:"status"` // active, expired, failed, pending
	ErrorMessage string          `json:"error_message,omitempty"`
	RefreshCount int             `json:"refresh_count"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// ConnectionStatistics representa estatísticas de conexão
type ConnectionStatistics struct {
	TotalConnections   int       `json:"total_connections"`
	ActiveConnections  int       `json:"active_connections"`
	ExpiredConnections int       `json:"expired_connections"`
	FailedConnections  int       `json:"failed_connections"`
	TotalRefreshes     int       `json:"total_refreshes"`
	LastRefreshTime    time.Time `json:"last_refresh_time"`
	AverageRefreshTime float64   `json:"average_refresh_time"`
}

// Global storage
var (
	connectionsMutex     sync.RWMutex
	accountConnections   map[string]*AccountConnection
	connectionStats      ConnectionStatistics
	refreshWorkerRunning bool
)

// initAWSSTSManager initializes the AWS STS Manager
func initAWSSTSManager() {
	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()

	accountConnections = make(map[string]*AccountConnection)
	connectionStats = ConnectionStatistics{
		LastRefreshTime: time.Now(),
	}

	// If we have environment-configured AWS credentials, create a connection for the primary account
	accountID := os.Getenv("AWS_ACCOUNT_ID")
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	if accountID != "" {
		conn := &AccountConnection{
			ID:          "conn-primary",
			AccountID:   accountID,
			AccountName: "Primary Account (ENV)",
			Region:      region,
			Status:      "pending",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		// Test the connection using environment credentials
		sess, err := getAWSSession()
		if err == nil {
			stsClient := sts.New(sess)
			result, callerErr := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
			if callerErr == nil {
				conn.Status = "active"
				conn.AccountID = aws.StringValue(result.Account)
				conn.LastRefresh = time.Now()
				conn.Credentials = &AWSCredentials{
					AccessKeyID: aws.StringValue(result.Arn),
					Expiration:  time.Now().Add(12 * time.Hour), // IAM role/user credentials don't expire the same way
					Region:      region,
				}
				log.Printf("✅ AWS STS Manager: Primary account %s connected (ARN: %s)",
					conn.AccountID, aws.StringValue(result.Arn))
			} else {
				conn.Status = "failed"
				conn.ErrorMessage = callerErr.Error()
				log.Printf("⚠️ AWS STS Manager: Failed to verify primary account: %v", callerErr)
			}
		} else {
			conn.Status = "failed"
			conn.ErrorMessage = err.Error()
			log.Printf("⚠️ AWS STS Manager: No AWS session available: %v", err)
		}

		accountConnections[conn.ID] = conn
	} else {
		log.Println("⚠️ AWS STS Manager: AWS_ACCOUNT_ID not set, no primary connection created")
	}

	updateConnectionStats()
	log.Printf("✅ AWS STS Manager initialized with %d connections", len(accountConnections))

	// Start background refresh worker
	if !refreshWorkerRunning {
		startCredentialRefreshWorker()
		refreshWorkerRunning = true
	}
}

// RefreshCredentials renova as credenciais usando AssumeRole
func (conn *AccountConnection) RefreshCredentials() error {
	startTime := time.Now()

	// If this is the primary connection (no RoleARN), just verify the session
	if conn.RoleARN == "" {
		sess, err := getAWSSession()
		if err != nil {
			conn.Status = "failed"
			conn.ErrorMessage = fmt.Sprintf("AWS session error: %v", err)
			return err
		}

		stsClient := sts.New(sess)
		result, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			conn.Status = "failed"
			conn.ErrorMessage = fmt.Sprintf("STS GetCallerIdentity failed: %v", err)
			return err
		}

		conn.Credentials = &AWSCredentials{
			AccessKeyID: aws.StringValue(result.Arn),
			Expiration:  time.Now().Add(12 * time.Hour),
			Region:      conn.Region,
		}
		conn.LastRefresh = time.Now()
		conn.Status = "active"
		conn.ErrorMessage = ""
		conn.RefreshCount++
		conn.UpdatedAt = time.Now()

		duration := time.Since(startTime).Seconds()
		log.Printf("✅ Credentials verified for primary account %s in %.2fs", conn.AccountID, duration)
		return nil
	}

	// For cross-account: use STS AssumeRole
	sess, err := getAWSSession()
	if err != nil {
		conn.Status = "failed"
		conn.ErrorMessage = fmt.Sprintf("AWS session error: %v", err)
		return err
	}

	stsClient := sts.New(sess)

	assumeInput := &sts.AssumeRoleInput{
		RoleArn:         aws.String(conn.RoleARN),
		RoleSessionName: aws.String(fmt.Sprintf("siem-platform-%s", conn.AccountID)),
		DurationSeconds: aws.Int64(3600), // 1 hour
	}
	if conn.ExternalID != "" {
		assumeInput.ExternalId = aws.String(conn.ExternalID)
	}

	result, err := stsClient.AssumeRole(assumeInput)
	if err != nil {
		conn.Status = "failed"
		conn.ErrorMessage = fmt.Sprintf("AssumeRole failed: %v", err)
		conn.UpdatedAt = time.Now()
		log.Printf("❌ Failed to assume role for account %s (%s): %v",
			conn.AccountID, conn.AccountName, err)
		return fmt.Errorf("failed to assume role: %w", err)
	}

	conn.Credentials = &AWSCredentials{
		AccessKeyID:     aws.StringValue(result.Credentials.AccessKeyId),
		SecretAccessKey: aws.StringValue(result.Credentials.SecretAccessKey),
		SessionToken:    aws.StringValue(result.Credentials.SessionToken),
		Expiration:      aws.TimeValue(result.Credentials.Expiration),
		Region:          conn.Region,
	}

	conn.LastRefresh = time.Now()
	conn.Status = "active"
	conn.ErrorMessage = ""
	conn.RefreshCount++
	conn.UpdatedAt = time.Now()

	duration := time.Since(startTime).Seconds()
	log.Printf("✅ Credentials refreshed for account %s (%s) via AssumeRole in %.2fs",
		conn.AccountID, conn.AccountName, duration)

	return nil
}

// IsExpired verifica se as credenciais expiraram
func (conn *AccountConnection) IsExpired() bool {
	if conn.Credentials == nil {
		return true
	}
	// Renova 5 minutos antes de expirar
	return time.Now().Add(5 * time.Minute).After(conn.Credentials.Expiration)
}

// TimeUntilExpiration retorna o tempo até a expiração
func (conn *AccountConnection) TimeUntilExpiration() time.Duration {
	if conn.Credentials == nil {
		return 0
	}
	remaining := time.Until(conn.Credentials.Expiration)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// GetConfigClient retorna um cliente AWS Config com credenciais atualizadas
func (conn *AccountConnection) GetConfigClient() (*configservice.ConfigService, error) {
	if conn.IsExpired() {
		if err := conn.RefreshCredentials(); err != nil {
			return nil, err
		}
	}

	if conn.Credentials == nil {
		return nil, fmt.Errorf("no credentials available for account %s", conn.AccountID)
	}

	// For primary connection (no RoleARN), use default session
	if conn.RoleARN == "" {
		sess, err := getAWSSession()
		if err != nil {
			return nil, err
		}
		return configservice.New(sess, aws.NewConfig().WithRegion(conn.Region)), nil
	}

	// For cross-account, use assumed role credentials
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(conn.Region),
		Credentials: credentials.NewStaticCredentials(
			conn.Credentials.AccessKeyID,
			conn.Credentials.SecretAccessKey,
			conn.Credentials.SessionToken,
		),
	})
	if err != nil {
		return nil, err
	}

	return configservice.New(sess), nil
}

// TestConnection testa a conexão com a conta AWS via STS GetCallerIdentity
func (conn *AccountConnection) TestConnection() error {
	if conn.RoleARN == "" {
		// For primary connection, test with environment credentials
		sess, err := getAWSSession()
		if err != nil {
			return fmt.Errorf("AWS session error: %w", err)
		}
		stsClient := sts.New(sess)
		_, err = stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			conn.Status = "failed"
			conn.ErrorMessage = err.Error()
			return fmt.Errorf("STS test failed: %w", err)
		}
		conn.Status = "active"
		conn.ErrorMessage = ""
		conn.UpdatedAt = time.Now()
		return nil
	}

	// For cross-account, test with AssumeRole
	if err := ValidateRoleARN(conn.RoleARN); err != nil {
		return err
	}

	return conn.RefreshCredentials()
}

// startCredentialRefreshWorker inicia o worker de renovação automática
func startCredentialRefreshWorker() {
	ticker := time.NewTicker(5 * time.Minute) // Verifica a cada 5 minutos

	go func() {
		log.Println("🔄 Credential refresh worker started")

		for range ticker.C {
			connectionsMutex.Lock()

			refreshed := 0
			failed := 0

			for _, conn := range accountConnections {
				if conn.IsExpired() {
					log.Printf("🔄 Refreshing credentials for account %s (%s)",
						conn.AccountID, conn.AccountName)

					if err := conn.RefreshCredentials(); err != nil {
						log.Printf("❌ Failed to refresh credentials for %s: %v",
							conn.AccountID, err)
						conn.Status = "failed"
						conn.ErrorMessage = err.Error()
						failed++
					} else {
						refreshed++
					}
				}
			}

			if refreshed > 0 || failed > 0 {
				log.Printf("🔄 Credential refresh cycle completed: %d refreshed, %d failed",
					refreshed, failed)
				updateConnectionStats()
			}

			connectionsMutex.Unlock()
		}
	}()
}

// updateConnectionStats atualiza as estatísticas de conexão
func updateConnectionStats() {
	connectionStats.TotalConnections = len(accountConnections)
	connectionStats.ActiveConnections = 0
	connectionStats.ExpiredConnections = 0
	connectionStats.FailedConnections = 0
	connectionStats.TotalRefreshes = 0

	for _, conn := range accountConnections {
		switch conn.Status {
		case "active":
			connectionStats.ActiveConnections++
		case "expired":
			connectionStats.ExpiredConnections++
		case "failed":
			connectionStats.FailedConnections++
		}
		connectionStats.TotalRefreshes += conn.RefreshCount
	}

	connectionStats.LastRefreshTime = time.Now()
}

// GetConnectionByAccountID retorna uma conexão pelo Account ID
func GetConnectionByAccountID(accountID string) (*AccountConnection, error) {
	connectionsMutex.RLock()
	defer connectionsMutex.RUnlock()

	for _, conn := range accountConnections {
		if conn.AccountID == accountID {
			return conn, nil
		}
	}

	return nil, fmt.Errorf("connection not found for account %s", accountID)
}

// ValidateRoleARN valida o formato do Role ARN
func ValidateRoleARN(roleARN string) error {
	if roleARN == "" {
		return fmt.Errorf("role ARN cannot be empty")
	}
	if len(roleARN) < 20 || roleARN[:13] != "arn:aws:iam::" {
		return fmt.Errorf("invalid role ARN format")
	}
	return nil
}

// GenerateExternalID gera um External ID único
func GenerateExternalID() string {
	return fmt.Sprintf("siem-platform-%d", time.Now().Unix())
}
