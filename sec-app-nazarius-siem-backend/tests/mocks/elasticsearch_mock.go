package mocks

import (
	"encoding/json"
	"fmt"
)

// MockElasticsearchClient simula um cliente Elasticsearch para testes
type MockElasticsearchClient struct {
	Documents map[string]interface{}
	Queries   []string
	IndexName string
}

// NewMockElasticsearchClient cria um novo mock do Elasticsearch
func NewMockElasticsearchClient() *MockElasticsearchClient {
	return &MockElasticsearchClient{
		Documents: make(map[string]interface{}),
		Queries:   make([]string, 0),
		IndexName: "test-index",
	}
}

// Index simula indexação de um documento
func (m *MockElasticsearchClient) Index(index, docID string, document interface{}) error {
	if index == "" || docID == "" {
		return fmt.Errorf("index e docID são obrigatórios")
	}

	key := fmt.Sprintf("%s:%s", index, docID)
	m.Documents[key] = document
	return nil
}

// Get simula busca de um documento por ID
func (m *MockElasticsearchClient) Get(index, docID string) (interface{}, error) {
	key := fmt.Sprintf("%s:%s", index, docID)
	doc, exists := m.Documents[key]
	if !exists {
		return nil, fmt.Errorf("documento não encontrado")
	}
	return doc, nil
}

// Search simula uma busca no Elasticsearch
func (m *MockElasticsearchClient) Search(index string, query map[string]interface{}) ([]interface{}, error) {
	m.Queries = append(m.Queries, fmt.Sprintf("%v", query))

	// Retorna todos os documentos do índice (simulação simplificada)
	results := make([]interface{}, 0)
	prefix := index + ":"
	for key, doc := range m.Documents {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			results = append(results, doc)
		}
	}

	return results, nil
}

// Delete simula deleção de um documento
func (m *MockElasticsearchClient) Delete(index, docID string) error {
	key := fmt.Sprintf("%s:%s", index, docID)
	delete(m.Documents, key)
	return nil
}

// BulkIndex simula indexação em massa
func (m *MockElasticsearchClient) BulkIndex(index string, documents []interface{}) error {
	for i, doc := range documents {
		docID := fmt.Sprintf("doc-%d", i)
		if err := m.Index(index, docID, doc); err != nil {
			return err
		}
	}
	return nil
}

// Count simula contagem de documentos
func (m *MockElasticsearchClient) Count(index string) (int, error) {
	count := 0
	prefix := index + ":"
	for key := range m.Documents {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			count++
		}
	}
	return count, nil
}

// Aggregate simula agregações
func (m *MockElasticsearchClient) Aggregate(index string, aggregation map[string]interface{}) (map[string]interface{}, error) {
	// Simulação simplificada de agregação
	result := map[string]interface{}{
		"aggregations": map[string]interface{}{
			"total": len(m.Documents),
			"buckets": []map[string]interface{}{
				{"key": "high", "doc_count": 10},
				{"key": "medium", "doc_count": 25},
				{"key": "low", "doc_count": 15},
			},
		},
	}
	return result, nil
}

// UpdateByQuery simula atualização por query
func (m *MockElasticsearchClient) UpdateByQuery(index string, query, script map[string]interface{}) (int, error) {
	// Simulação: atualiza todos os documentos que correspondem
	updated := 0
	prefix := index + ":"
	for key := range m.Documents {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			updated++
		}
	}
	return updated, nil
}

// CreateIndex simula criação de índice
func (m *MockElasticsearchClient) CreateIndex(index string, mapping map[string]interface{}) error {
	if index == "" {
		return fmt.Errorf("nome do índice é obrigatório")
	}
	m.IndexName = index
	return nil
}

// DeleteIndex simula deleção de índice
func (m *MockElasticsearchClient) DeleteIndex(index string) error {
	// Remove todos os documentos do índice
	prefix := index + ":"
	for key := range m.Documents {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			delete(m.Documents, key)
		}
	}
	return nil
}

// Refresh simula refresh de índice
func (m *MockElasticsearchClient) Refresh(index string) error {
	// Não faz nada no mock
	return nil
}

// Health simula verificação de saúde do cluster
func (m *MockElasticsearchClient) Health() (map[string]interface{}, error) {
	return map[string]interface{}{
		"status":         "green",
		"cluster_name":   "mock-cluster",
		"number_of_nodes": 1,
		"active_shards":   5,
	}, nil
}

// MockSearchResponse representa uma resposta de busca mockada
type MockSearchResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			ID     string                 `json:"_id"`
			Source map[string]interface{} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// GenerateMockSearchResponse gera uma resposta de busca mockada
func GenerateMockSearchResponse(numHits int) []byte {
	response := MockSearchResponse{}
	response.Hits.Total.Value = numHits

	response.Hits.Hits = make([]struct {
		ID     string                 `json:"_id"`
		Source map[string]interface{} `json:"_source"`
	}, numHits)

	for i := 0; i < numHits; i++ {
		response.Hits.Hits[i].ID = fmt.Sprintf("doc-%d", i)
		response.Hits.Hits[i].Source = map[string]interface{}{
			"timestamp": "2025-11-07T10:00:00Z",
			"severity":  "high",
			"message":   fmt.Sprintf("Mock event %d", i),
		}
	}

	data, _ := json.Marshal(response)
	return data
}

// Reset limpa todos os dados do mock
func (m *MockElasticsearchClient) Reset() {
	m.Documents = make(map[string]interface{})
	m.Queries = make([]string, 0)
}

// GetQueryHistory retorna histórico de queries executadas
func (m *MockElasticsearchClient) GetQueryHistory() []string {
	return m.Queries
}

