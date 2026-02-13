package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/gin-gonic/gin"
	"github.com/opensearch-project/opensearch-go/v2/opensearchapi"
)

// AWSDiagnosticsResult contains the diagnostic results
type AWSDiagnosticsResult struct {
	Timestamp           time.Time                  `json:"timestamp"`
	Region              string                     `json:"region"`
	UseRealAWSData      bool                       `json:"use_real_aws_data"`
	
	// AWS Inspector Status
	InspectorStatus     InspectorDiagnostics       `json:"inspector"`
	
	// Security Hub Status
	SecurityHubStatus   SecurityHubDiagnostics     `json:"security_hub"`
	
	// OpenSearch Status
	OpenSearchStatus    OpenSearchDiagnostics      `json:"opensearch"`
	
	// Recommendations
	Recommendations     []string                   `json:"recommendations"`
}

// InspectorDiagnostics contains Inspector diagnostic info
type InspectorDiagnostics struct {
	Connected           bool                       `json:"connected"`
	Enabled             bool                       `json:"enabled"`
	Error               string                     `json:"error,omitempty"`
	AccountID           string                     `json:"account_id,omitempty"`
	EC2Scanning         bool                       `json:"ec2_scanning"`
	ECRScanning         bool                       `json:"ecr_scanning"`
	LambdaScanning      bool                       `json:"lambda_scanning"`
	TotalFindings       int                        `json:"total_findings"`
	CriticalFindings    int                        `json:"critical_findings"`
	HighFindings        int                        `json:"high_findings"`
	SampleFindings      []map[string]interface{}   `json:"sample_findings,omitempty"`
}

// SecurityHubDiagnostics contains Security Hub diagnostic info
type SecurityHubDiagnostics struct {
	Connected           bool                       `json:"connected"`
	Enabled             bool                       `json:"enabled"`
	Error               string                     `json:"error,omitempty"`
	HubARN              string                     `json:"hub_arn,omitempty"`
	TotalFindings       int                        `json:"total_findings"`
	InspectorFindings   int                        `json:"inspector_findings"`
	SampleFindings      []map[string]interface{}   `json:"sample_findings,omitempty"`
}

// OpenSearchDiagnostics contains OpenSearch diagnostic info
type OpenSearchDiagnostics struct {
	Connected           bool                       `json:"connected"`
	Error               string                     `json:"error,omitempty"`
	VulnerabilitiesIndex struct {
		Exists          bool                       `json:"exists"`
		DocumentCount   int                        `json:"document_count"`
		SizeBytes       int64                      `json:"size_bytes"`
	} `json:"vulnerabilities_index"`
}

// handleAWSDiagnostics runs diagnostics on AWS connectivity and data collection
func (s *APIServer) handleAWSDiagnostics(c *gin.Context) {
	result := AWSDiagnosticsResult{
		Timestamp:       time.Now(),
		Region:          os.Getenv("AWS_REGION"),
		UseRealAWSData:  os.Getenv("USE_REAL_AWS_DATA") == "true",
		Recommendations: []string{},
	}
	
	if result.Region == "" {
		result.Region = "us-east-1"
	}
	
	// Check environment variables
	if !result.UseRealAWSData {
		result.Recommendations = append(result.Recommendations, 
			"⚠️ USE_REAL_AWS_DATA não está definido como 'true'. Defina esta variável de ambiente no ECS Task Definition para ativar dados reais.")
	}
	
	// Check AWS Inspector
	result.InspectorStatus = s.checkInspectorDiag(result.Region)
	
	// Check Security Hub
	result.SecurityHubStatus = s.checkSecurityHubDiag(result.Region)
	
	// Check OpenSearch
	result.OpenSearchStatus = s.checkOpenSearchDiag()
	
	// Generate recommendations
	if !result.InspectorStatus.Connected {
		result.Recommendations = append(result.Recommendations,
			"❌ Não foi possível conectar ao AWS Inspector. Verifique as credenciais IAM do ECS Task Role.")
	} else if !result.InspectorStatus.Enabled {
		result.Recommendations = append(result.Recommendations,
			"⚠️ AWS Inspector v2 não está ativado. Acesse o Console AWS > Inspector > Settings para ativar.")
	} else if result.InspectorStatus.TotalFindings == 0 {
		result.Recommendations = append(result.Recommendations,
			"ℹ️ AWS Inspector está ativo mas não encontrou vulnerabilidades. Verifique se há recursos (EC2/ECR/Lambda) sendo escaneados.")
	}
	
	if !result.SecurityHubStatus.Connected {
		result.Recommendations = append(result.Recommendations,
			"❌ Não foi possível conectar ao Security Hub. Verifique as permissões IAM.")
	} else if result.SecurityHubStatus.InspectorFindings == 0 {
		result.Recommendations = append(result.Recommendations,
			"ℹ️ Security Hub não tem findings do Inspector. Verifique se a integração Inspector -> Security Hub está ativa.")
	}
	
	if !result.OpenSearchStatus.Connected {
		result.Recommendations = append(result.Recommendations,
			"❌ Não foi possível conectar ao OpenSearch. Verifique a configuração OPENSEARCH_URL.")
	} else if result.OpenSearchStatus.VulnerabilitiesIndex.DocumentCount == 0 {
		result.Recommendations = append(result.Recommendations,
			"ℹ️ Índice de vulnerabilidades está vazio. O coletor precisa indexar dados do Inspector.")
	}
	
	if len(result.Recommendations) == 0 {
		result.Recommendations = append(result.Recommendations,
			"✅ Tudo configurado corretamente! Os dados do Inspector devem aparecer em breve.")
	}
	
	c.JSON(http.StatusOK, result)
}

// checkInspectorDiag checks AWS Inspector v2 status
func (s *APIServer) checkInspectorDiag(region string) InspectorDiagnostics {
	diag := InspectorDiagnostics{}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		diag.Error = "Falha ao carregar configuração AWS: " + err.Error()
		return diag
	}
	
	client := inspector2.NewFromConfig(cfg)
	
	// Check if Inspector is enabled
	statusOutput, err := client.BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{})
	if err != nil {
		diag.Error = "Falha ao verificar status do Inspector: " + err.Error()
		return diag
	}
	
	diag.Connected = true
	
	if len(statusOutput.Accounts) > 0 {
		account := statusOutput.Accounts[0]
		diag.AccountID = *account.AccountId
		diag.Enabled = account.State.Status == types.StatusEnabled
		
		// Check resource types being scanned
		if account.ResourceState.Ec2 != nil {
			diag.EC2Scanning = account.ResourceState.Ec2.Status == types.StatusEnabled
		}
		if account.ResourceState.Ecr != nil {
			diag.ECRScanning = account.ResourceState.Ecr.Status == types.StatusEnabled
		}
		if account.ResourceState.Lambda != nil {
			diag.LambdaScanning = account.ResourceState.Lambda.Status == types.StatusEnabled
		}
	}
	
	// Get finding counts
	findingsOutput, err := client.ListFindings(ctx, &inspector2.ListFindingsInput{
		MaxResults: aws.Int32(100),
	})
	if err != nil {
		log.Printf("⚠️ Falha ao listar findings: %v", err)
	} else {
		diag.TotalFindings = len(findingsOutput.Findings)
		
		for _, f := range findingsOutput.Findings {
			if f.Severity == types.SeverityCritical {
				diag.CriticalFindings++
			} else if f.Severity == types.SeverityHigh {
				diag.HighFindings++
			}
		}
		
		// Get sample findings (first 3)
		for i, f := range findingsOutput.Findings {
			if i >= 3 {
				break
			}
			sample := map[string]interface{}{
				"severity":    string(f.Severity),
				"type":        string(f.Type),
				"status":      string(f.Status),
			}
			if f.FindingArn != nil {
				sample["id"] = *f.FindingArn
			}
			if f.Title != nil {
				sample["title"] = *f.Title
			}
			if f.PackageVulnerabilityDetails != nil && f.PackageVulnerabilityDetails.VulnerabilityId != nil {
				sample["cve"] = *f.PackageVulnerabilityDetails.VulnerabilityId
			}
			diag.SampleFindings = append(diag.SampleFindings, sample)
		}
	}
	
	return diag
}

// checkSecurityHubDiag checks Security Hub status
func (s *APIServer) checkSecurityHubDiag(region string) SecurityHubDiagnostics {
	diag := SecurityHubDiagnostics{}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		diag.Error = "Falha ao carregar configuração AWS: " + err.Error()
		return diag
	}
	
	client := securityhub.NewFromConfig(cfg)
	
	// Check if Security Hub is enabled
	hubOutput, err := client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		diag.Error = "Security Hub não está ativo ou sem permissão: " + err.Error()
		return diag
	}
	
	diag.Connected = true
	diag.Enabled = true
	if hubOutput.HubArn != nil {
		diag.HubARN = *hubOutput.HubArn
	}
	
	// Get findings from Inspector
	findingsOutput, err := client.GetFindings(ctx, &securityhub.GetFindingsInput{
		MaxResults: aws.Int32(100),
		Filters: &securityhubtypes.AwsSecurityFindingFilters{
			ProductName: []securityhubtypes.StringFilter{
				{
					Value:      aws.String("Inspector"),
					Comparison: securityhubtypes.StringFilterComparisonEquals,
				},
			},
		},
	})
	if err != nil {
		log.Printf("⚠️ Falha ao buscar findings do Security Hub: %v", err)
	} else {
		diag.TotalFindings = len(findingsOutput.Findings)
		diag.InspectorFindings = len(findingsOutput.Findings)
		
		// Get sample findings (first 3)
		for i, f := range findingsOutput.Findings {
			if i >= 3 {
				break
			}
			sample := map[string]interface{}{}
			if f.Id != nil {
				sample["id"] = *f.Id
			}
			if f.Title != nil {
				sample["title"] = *f.Title
			}
			if f.Severity != nil {
				sample["severity"] = string(f.Severity.Label)
			}
			if f.ProductName != nil {
				sample["product"] = *f.ProductName
			}
			diag.SampleFindings = append(diag.SampleFindings, sample)
		}
	}
	
	return diag
}

// checkOpenSearchDiag checks OpenSearch status
func (s *APIServer) checkOpenSearchDiag() OpenSearchDiagnostics {
	diag := OpenSearchDiagnostics{}
	
	if s.opensearch == nil {
		diag.Error = "Cliente OpenSearch não inicializado"
		return diag
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Check cluster health
	res, err := s.opensearch.Cluster.Health(
		s.opensearch.Cluster.Health.WithContext(ctx),
	)
	if err != nil {
		diag.Error = "Falha ao conectar ao OpenSearch: " + err.Error()
		return diag
	}
	defer res.Body.Close()
	
	if res.IsError() {
		diag.Error = "Erro no cluster OpenSearch: " + res.String()
		return diag
	}
	
	diag.Connected = true
	
	// Check vulnerabilities index
	indexReq := opensearchapi.CatIndicesRequest{
		Index:  []string{"siem-vulnerabilities"},
		Format: "json",
	}
	
	indexRes, err := indexReq.Do(ctx, s.opensearch)
	if err != nil {
		log.Printf("⚠️ Falha ao verificar índice: %v", err)
		return diag
	}
	defer indexRes.Body.Close()
	
	if !indexRes.IsError() {
		var indices []map[string]interface{}
		if err := json.NewDecoder(indexRes.Body).Decode(&indices); err == nil && len(indices) > 0 {
			diag.VulnerabilitiesIndex.Exists = true
			if count, ok := indices[0]["docs.count"].(string); ok {
				var c int
				json.Unmarshal([]byte(count), &c)
				diag.VulnerabilitiesIndex.DocumentCount = c
			}
		}
	}
	
	return diag
}

// handleForceInspectorSync forces an immediate sync from Inspector
func (s *APIServer) handleForceInspectorSync(c *gin.Context) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	
	// Initialize collector
	collector, err := InitInspectorCollector(region, s.opensearch)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Falha ao inicializar coletor",
			"details": err.Error(),
		})
		return
	}
	
	// Run collection
	go func() {
		log.Println("🔄 Iniciando sincronização manual do Inspector...")
		ctx := context.Background()
		
		findings, err := collector.CollectFindings(ctx)
		if err != nil {
			log.Printf("❌ Erro ao coletar findings: %v", err)
			return
		}
		
		log.Printf("📊 Coletados %d findings do Inspector", len(findings))
		
		if len(findings) > 0 {
			if err := collector.IndexFindings(ctx, findings); err != nil {
				log.Printf("❌ Erro ao indexar findings: %v", err)
				return
			}
		}
		
		log.Println("✅ Sincronização do Inspector concluída")
	}()
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Sincronização iniciada em background",
		"note":    "Verifique os logs do CloudWatch para acompanhar o progresso",
	})
}
