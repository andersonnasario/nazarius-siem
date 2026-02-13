package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

// AWSCredentialsProvider gerencia credenciais AWS de múltiplas fontes
type AWSCredentialsProvider struct {
	session          *session.Session
	isRunningInAWS   bool
	instanceRegion   string
	instanceAccountID string
	instanceRoleARN  string
}

// CredentialSource indica a origem das credenciais
type CredentialSource string

const (
	CredentialSourceInstanceProfile CredentialSource = "instance_profile" // EC2 Instance Profile
	CredentialSourceTaskRole        CredentialSource = "task_role"        // ECS Task Role
	CredentialSourceLambdaRole      CredentialSource = "lambda_role"      // Lambda Execution Role
	CredentialSourceAssumeRole      CredentialSource = "assume_role"      // AssumeRole (cross-account)
	CredentialSourceConnections     CredentialSource = "connections"      // AWS Connections Manager
	CredentialSourceEnvironment     CredentialSource = "environment"      // Environment variables
)

// AWSCredentialInfo contém informações sobre as credenciais em uso
type AWSCredentialInfo struct {
	Source      CredentialSource `json:"source"`
	Region      string           `json:"region"`
	AccountID   string           `json:"account_id"`
	RoleARN     string           `json:"role_arn,omitempty"`
	ExpiresAt   *time.Time       `json:"expires_at,omitempty"`
	Description string           `json:"description"`
}

// NewAWSCredentialsProvider cria um novo provider de credenciais
func NewAWSCredentialsProvider() (*AWSCredentialsProvider, error) {
	provider := &AWSCredentialsProvider{}
	
	// Detecta se está rodando na AWS
	if err := provider.detectAWSEnvironment(); err != nil {
		log.Printf("⚠️  Not running in AWS environment: %v", err)
		provider.isRunningInAWS = false
	}
	
	return provider, nil
}

// detectAWSEnvironment detecta se está rodando na AWS e obtém metadados
func (p *AWSCredentialsProvider) detectAWSEnvironment() error {
	// Cria sessão básica para acessar metadata service
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"), // região padrão para metadata
	})
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	
	// Tenta acessar EC2 metadata service
	metadataClient := ec2metadata.New(sess)
	
	// Timeout curto para não travar se não estiver na AWS
	metadataClient.Config.HTTPClient.Timeout = 2 * time.Second
	
	if !metadataClient.Available() {
		return fmt.Errorf("EC2 metadata service not available")
	}
	
	p.isRunningInAWS = true
	
	// Obtém região da instância
	if region, err := metadataClient.Region(); err == nil {
		p.instanceRegion = region
		log.Printf("✅ Detected AWS region: %s", region)
	}
	
	// Obtém IAM role da instância
	if iamInfo, err := metadataClient.IAMInfo(); err == nil {
		p.instanceRoleARN = iamInfo.InstanceProfileArn
		log.Printf("✅ Detected IAM Instance Profile: %s", iamInfo.InstanceProfileArn)
	}
	
	// Cria sessão com credenciais da instância
	p.session, err = session.NewSession(&aws.Config{
		Region: aws.String(p.instanceRegion),
	})
	if err != nil {
		return fmt.Errorf("failed to create AWS session: %w", err)
	}
	
	// Obtém Account ID usando STS
	stsClient := sts.New(p.session)
	identity, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err == nil {
		p.instanceAccountID = aws.StringValue(identity.Account)
		log.Printf("✅ Detected AWS Account ID: %s", p.instanceAccountID)
	}
	
	return nil
}

// IsRunningInAWS retorna true se está rodando na AWS
func (p *AWSCredentialsProvider) IsRunningInAWS() bool {
	return p.isRunningInAWS
}

// GetInstanceCredentials retorna credenciais da instância/task/lambda
func (p *AWSCredentialsProvider) GetInstanceCredentials() (*AWSCredentialInfo, *session.Session, error) {
	if !p.isRunningInAWS {
		return nil, nil, fmt.Errorf("not running in AWS environment")
	}
	
	// Detecta tipo de ambiente
	var source CredentialSource
	var description string
	
	if os.Getenv("AWS_EXECUTION_ENV") != "" {
		// Lambda
		source = CredentialSourceLambdaRole
		description = "Using Lambda Execution Role"
	} else if os.Getenv("ECS_CONTAINER_METADATA_URI") != "" || os.Getenv("ECS_CONTAINER_METADATA_URI_V4") != "" {
		// ECS
		source = CredentialSourceTaskRole
		description = "Using ECS Task Role"
	} else {
		// EC2
		source = CredentialSourceInstanceProfile
		description = "Using EC2 Instance Profile"
	}
	
	info := &AWSCredentialInfo{
		Source:      source,
		Region:      p.instanceRegion,
		AccountID:   p.instanceAccountID,
		RoleARN:     p.instanceRoleARN,
		Description: description,
	}
	
	log.Printf("✅ %s (Account: %s, Region: %s)", description, p.instanceAccountID, p.instanceRegion)
	
	return info, p.session, nil
}

// GetAssumeRoleCredentials obtém credenciais via AssumeRole para cross-account
func (p *AWSCredentialsProvider) GetAssumeRoleCredentials(roleARN, externalID, sessionName string, duration int) (*AWSCredentialInfo, *session.Session, error) {
	if !p.isRunningInAWS {
		return nil, nil, fmt.Errorf("not running in AWS environment - cannot assume role")
	}
	
	if sessionName == "" {
		sessionName = fmt.Sprintf("siem-platform-%d", time.Now().Unix())
	}
	
	log.Printf("🔄 Assuming role: %s", roleARN)
	
	// Cria credenciais usando AssumeRole
	creds := stscreds.NewCredentials(p.session, roleARN, func(p *stscreds.AssumeRoleProvider) {
		p.ExternalID = aws.String(externalID)
		p.RoleSessionName = sessionName
		p.Duration = time.Duration(duration) * time.Second
	})
	
	// Cria nova sessão com as credenciais assumidas
	assumedSession, err := session.NewSession(&aws.Config{
		Region:      aws.String(p.instanceRegion),
		Credentials: creds,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session with assumed role: %w", err)
	}
	
	// Verifica se as credenciais funcionam
	stsClient := sts.New(assumedSession)
	identity, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify assumed role credentials: %w", err)
	}
	
	// Calcula expiração
	expiresAt := time.Now().Add(time.Duration(duration) * time.Second)
	
	info := &AWSCredentialInfo{
		Source:      CredentialSourceAssumeRole,
		Region:      p.instanceRegion,
		AccountID:   aws.StringValue(identity.Account),
		RoleARN:     roleARN,
		ExpiresAt:   &expiresAt,
		Description: fmt.Sprintf("Assumed role: %s", roleARN),
	}
	
	log.Printf("✅ Successfully assumed role: %s (Account: %s)", roleARN, info.AccountID)
	
	return info, assumedSession, nil
}

// GetCredentialsFromConnection obtém credenciais do AWS Connections Manager
func (p *AWSCredentialsProvider) GetCredentialsFromConnection(conn *AccountConnection) (*AWSCredentialInfo, *session.Session, error) {
	if conn == nil {
		return nil, nil, fmt.Errorf("connection is nil")
	}
	
	if conn.Credentials == nil || time.Now().After(conn.Credentials.Expiration) {
		log.Printf("⚠️  Connection '%s' credentials expired, refreshing...", conn.AccountName)
		if err := conn.RefreshCredentials(); err != nil {
			return nil, nil, fmt.Errorf("failed to refresh credentials: %w", err)
		}
	}
	
	// Cria sessão com credenciais da conexão
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(conn.Region),
		Credentials: credentials.NewStaticCredentials(
			conn.Credentials.AccessKeyID,
			conn.Credentials.SecretAccessKey,
			conn.Credentials.SessionToken,
		),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}
	
	info := &AWSCredentialInfo{
		Source:      CredentialSourceConnections,
		Region:      conn.Region,
		AccountID:   conn.AccountID,
		RoleARN:     conn.RoleARN,
		ExpiresAt:   &conn.Credentials.Expiration,
		Description: fmt.Sprintf("AWS Connection: %s", conn.AccountName),
	}
	
	log.Printf("✅ Using AWS Connection: %s (Account: %s)", conn.AccountName, conn.AccountID)
	
	return info, sess, nil
}

// GetBestCredentials retorna as melhores credenciais disponíveis
// Prioridade: Instance Profile > AWS Connections > Environment Variables
func (p *AWSCredentialsProvider) GetBestCredentials() (*AWSCredentialInfo, *session.Session, error) {
	// 1. Tenta usar credenciais da instância (mais seguro)
	if p.isRunningInAWS {
		log.Printf("🔍 Running in AWS - using native IAM credentials")
		return p.GetInstanceCredentials()
	}
	
	// 2. Tenta usar AWS Connections Manager
	log.Printf("🔍 Not in AWS - checking AWS Connections Manager...")
	conn := getActiveAWSConnection()
	if conn != nil {
		return p.GetCredentialsFromConnection(conn)
	}
	
	// 3. Fallback para variáveis de ambiente (menos seguro)
	log.Printf("⚠️  No AWS Connections found - checking environment variables...")
	if accessKey := os.Getenv("AWS_ACCESS_KEY_ID"); accessKey != "" {
		secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}
		
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(region),
			Credentials: credentials.NewStaticCredentials(
				accessKey,
				secretKey,
				os.Getenv("AWS_SESSION_TOKEN"),
			),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create session from environment: %w", err)
		}
		
		// Obtém Account ID
		stsClient := sts.New(sess)
		identity, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
		accountID := "unknown"
		if err == nil {
			accountID = aws.StringValue(identity.Account)
		}
		
		info := &AWSCredentialInfo{
			Source:      CredentialSourceEnvironment,
			Region:      region,
			AccountID:   accountID,
			Description: "Using environment variables (not recommended for production)",
		}
		
		log.Printf("⚠️  Using environment variables (Account: %s)", accountID)
		
		return info, sess, nil
	}
	
	return nil, nil, fmt.Errorf("no AWS credentials available")
}

// GetMultiAccountCredentials retorna credenciais para múltiplas contas
// Usa Instance Profile + AssumeRole para cross-account
func (p *AWSCredentialsProvider) GetMultiAccountCredentials() ([]*AWSCredentialInfo, error) {
	credentials := []*AWSCredentialInfo{}
	
	// 1. Adiciona credenciais da conta atual
	if p.isRunningInAWS {
		info, _, err := p.GetInstanceCredentials()
		if err == nil {
			credentials = append(credentials, info)
		}
	}
	
	// 2. Adiciona credenciais de outras contas via AssumeRole
	connectionsMutex.RLock()
	defer connectionsMutex.RUnlock()
	
	for _, conn := range accountConnections {
		if conn.Status == "active" && conn.RoleARN != "" {
			// Se estiver na AWS, usa AssumeRole
			if p.isRunningInAWS {
				info, _, err := p.GetAssumeRoleCredentials(
					conn.RoleARN,
					conn.ExternalID,
					fmt.Sprintf("siem-%s", conn.AccountName),
					3600,
				)
				if err != nil {
					log.Printf("⚠️  Failed to assume role for %s: %v", conn.AccountName, err)
					continue
				}
				credentials = append(credentials, info)
			} else {
				// Se não estiver na AWS, usa credenciais da conexão
				info, _, err := p.GetCredentialsFromConnection(conn)
				if err != nil {
					log.Printf("⚠️  Failed to get credentials for %s: %v", conn.AccountName, err)
					continue
				}
				credentials = append(credentials, info)
			}
		}
	}
	
	return credentials, nil
}

