package main

import "github.com/gin-gonic/gin"

// ============================================================================
// ROLE-BASED ACCESS SCOPE CONFIGURATION
// ============================================================================
// Configuração de escopos por role - permite restringir acesso a account_ids
// específicos baseado no role do usuário.

// RoleScopeConfig define os escopos permitidos para um role específico
type RoleScopeConfig struct {
	AccountIDs  []string
	BucketNames []string
	Description string
}

// roleScopeConfigs mapeia roles para seus escopos de acesso
// Roles não listados aqui têm acesso irrestrito (exceto admin que sempre tem acesso total)
var roleScopeConfigs = map[string]RoleScopeConfig{
	"banking": {
		AccountIDs: []string{
			"379334555230", // banking-prd
			"039663229792", // banking-dev
			"334931733882", // banking-hml
		},
		Description: "Acesso restrito aos ambientes Banking (PRD, HML, DEV)",
	},
	// Adicione outros roles com escopo restrito aqui:
	// "fintech": {
	//     AccountIDs: []string{"111111111111", "222222222222"},
	//     Description: "Acesso restrito aos ambientes Fintech",
	// },
}

// AccessScope representa o escopo de acesso do usuário atual
type AccessScope struct {
	AccountIDs  []string
	BucketNames []string
}

func getAccessScope(c *gin.Context) AccessScope {
	// Admin sempre tem acesso total
	if isAdminRole(c) {
		return AccessScope{}
	}

	scope := AccessScope{}

	// 1. Primeiro, verificar se há escopos individuais definidos no usuário
	if v, ok := c.Get("allowed_account_ids"); ok {
		if ids, ok := v.([]string); ok && len(ids) > 0 {
			scope.AccountIDs = ids
		}
	}
	if v, ok := c.Get("allowed_bucket_names"); ok {
		if names, ok := v.([]string); ok && len(names) > 0 {
			scope.BucketNames = names
		}
	}

	// 2. Se não há escopos individuais, aplicar escopos do role
	if len(scope.AccountIDs) == 0 && len(scope.BucketNames) == 0 {
		roleName := getRoleName(c)
		if roleConfig, exists := roleScopeConfigs[roleName]; exists {
			scope.AccountIDs = roleConfig.AccountIDs
			scope.BucketNames = roleConfig.BucketNames
		}
	}

	return scope
}

// getRoleName retorna o nome do role do usuário atual
func getRoleName(c *gin.Context) string {
	if roleName, ok := c.Get("role_name"); ok {
		if name, ok := roleName.(string); ok {
			return name
		}
	}
	return ""
}

func isAdminRole(c *gin.Context) bool {
	roleName, ok := c.Get("role_name")
	if !ok {
		return false
	}
	return roleName == "admin"
}

func buildEventAccessFilter(scope AccessScope) []map[string]interface{} {
	should := []map[string]interface{}{}

	if len(scope.AccountIDs) > 0 {
		// Buscar em vários campos possíveis onde o account_id pode estar:
		// 1. details.account_id (CloudTrail, GuardDuty, Security Hub - eventos SIEM)
		should = append(should, map[string]interface{}{
			"terms": map[string]interface{}{
				"details.account_id": scope.AccountIDs,
			},
		})
		// 2. account_id no nível raiz
		should = append(should, map[string]interface{}{
			"terms": map[string]interface{}{
				"account_id": scope.AccountIDs,
			},
		})
		// 3. aws_account_id no nível raiz (Inspector/Security Hub vulnerabilities)
		should = append(should, map[string]interface{}{
			"terms": map[string]interface{}{
				"aws_account_id": scope.AccountIDs,
			},
		})
		// 4. details.aws_account_id (alternativo)
		should = append(should, map[string]interface{}{
			"terms": map[string]interface{}{
				"details.aws_account_id": scope.AccountIDs,
			},
		})
		// 5. details.recipientAccountId (CloudTrail específico)
		should = append(should, map[string]interface{}{
			"terms": map[string]interface{}{
				"details.recipientAccountId": scope.AccountIDs,
			},
		})
		// NÃO incluir eventos sem account_id - usuários com escopo restrito
		// só devem ver eventos que explicitamente pertencem ao seu escopo
	}

	if len(scope.BucketNames) > 0 {
		should = append(should, map[string]interface{}{
			"terms": map[string]interface{}{
				"details.request_parameters.bucketName": scope.BucketNames,
			},
		})
	}

	if len(should) == 0 {
		return nil
	}
	return []map[string]interface{}{
		{
			"bool": map[string]interface{}{
				"should":               should,
				"minimum_should_match": 1,
			},
		},
	}
}

func buildAlertAccessFilter(scope AccessScope) []map[string]interface{} {
	if len(scope.AccountIDs) == 0 {
		return nil
	}
	// Buscar APENAS alertas que têm account_id no escopo permitido
	// Usuários com perfil restrito só veem alertas do seu escopo
	// NÃO incluir alertas sem account_id - isso garante isolamento entre perfis
	return []map[string]interface{}{
		{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					// Alertas com account_id no nível raiz
					{"terms": map[string]interface{}{"account_id": scope.AccountIDs}},
					// Alertas com account_id em metadata
					{"terms": map[string]interface{}{"metadata.account_id": scope.AccountIDs}},
					// Alertas com account_id em details
					{"terms": map[string]interface{}{"details.account_id": scope.AccountIDs}},
				},
				"minimum_should_match": 1,
			},
		},
	}
}

func buildCaseAccessFilter(scope AccessScope) []map[string]interface{} {
	if len(scope.AccountIDs) == 0 {
		return nil
	}
	// Buscar APENAS casos que têm account_id no escopo permitido
	// Usuários com perfil restrito (ex: Banking) só veem casos do seu escopo
	// NÃO incluir casos sem account_id - isso impede vazamento de dados entre perfis
	return []map[string]interface{}{
		{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					// Casos com account_id (snake_case - CaseOpenSearch)
					{"terms": map[string]interface{}{"account_id": scope.AccountIDs}},
					// Casos com accountId (camelCase - Case struct legado)
					{"terms": map[string]interface{}{"accountId": scope.AccountIDs}},
				},
				"minimum_should_match": 1,
			},
		},
	}
}

func eventMatchesScope(source map[string]interface{}, scope AccessScope) bool {
	if len(scope.AccountIDs) == 0 && len(scope.BucketNames) == 0 {
		return true
	}

	details, _ := source["details"].(map[string]interface{})

	// Buscar account_id em vários campos possíveis
	accountID := getStringFromMap(details, "account_id")
	if accountID == "" {
		accountID = getStringFromMap(source, "account_id")
	}
	if accountID == "" {
		accountID = getStringFromMap(source, "aws_account_id") // Inspector/Security Hub no nível raiz
	}
	if accountID == "" {
		accountID = getStringFromMap(details, "aws_account_id")
	}
	if accountID == "" {
		accountID = getStringFromMap(details, "recipientAccountId")
	}

	// Se encontrou account_id, verificar se está no escopo
	if accountID != "" {
		return stringInSlice(accountID, scope.AccountIDs)
	}

	// Verificar buckets
	if len(scope.BucketNames) > 0 {
		if params, ok := details["request_parameters"].(map[string]interface{}); ok {
			if bucketName, ok := params["bucketName"].(string); ok && stringInSlice(bucketName, scope.BucketNames) {
				return true
			}
			if bucketName, ok := params["bucket_name"].(string); ok && stringInSlice(bucketName, scope.BucketNames) {
				return true
			}
		}
	}

	// Eventos sem account_id identificável - não permitir para usuários com escopo restrito
	return false
}

func alertMatchesScope(alert Alert, scope AccessScope) bool {
	if len(scope.AccountIDs) == 0 {
		return true
	}
	// Se o alerta tem account_id, verificar se está no escopo
	if alert.AccountID != "" {
		return stringInSlice(alert.AccountID, scope.AccountIDs)
	}
	// Alertas sem account_id NÃO são permitidos para perfis com escopo restrito
	// Isso garante isolamento entre perfis (ex: Banking não vê alertas de outros perfis)
	return false
}

func stringInSlice(value string, list []string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// getStringFromMap está definido em alerts.go
