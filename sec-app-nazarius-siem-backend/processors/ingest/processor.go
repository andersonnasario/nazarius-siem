package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
)

type Event struct {
	Type      string                 `json:"type"`
	Timestamp time.Time             `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

type NormalizedEvent struct {
	ID            string                 `json:"id"`
	Source        string                 `json:"source"`
	Type          string                 `json:"type"`
	Timestamp     time.Time             `json:"timestamp"`
	Severity      string                 `json:"severity"`
	Account       string                 `json:"account"`
	Region        string                 `json:"region"`
	Resource      string                 `json:"resource"`
	Action        string                 `json:"action"`
	Actor         string                 `json:"actor"`
	RawData       map[string]interface{} `json:"raw_data"`
	EnrichedData  map[string]interface{} `json:"enriched_data"`
}

func (p *IngestPipeline) processMessages(topic string, consumer *kafka.Reader, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			message, err := consumer.ReadMessage(p.ctx)
			if err != nil {
				if err != context.Canceled {
					log.Printf("Erro ao ler mensagem do Kafka: %v", err)
				}
				continue
			}

			// Decodificar evento
			var event Event
			if err := json.Unmarshal(message.Value, &event); err != nil {
				log.Printf("Erro ao decodificar mensagem: %v", err)
				continue
			}

			// Normalizar evento
			normalized, err := p.normalizeEvent(event)
			if err != nil {
				log.Printf("Erro ao normalizar evento: %v", err)
				continue
			}

			// Enriquecer evento
			if err := p.enrichEvent(normalized); err != nil {
				log.Printf("Erro ao enriquecer evento: %v", err)
			}

			// Indexar no Elasticsearch
			if err := p.indexEvent(normalized); err != nil {
				log.Printf("Erro ao indexar evento: %v", err)
				continue
			}
		}
	}
}

func (p *IngestPipeline) normalizeEvent(event Event) (*NormalizedEvent, error) {
	normalized := &NormalizedEvent{
		ID:        generateEventID(),
		Source:    "aws",
		Type:      event.Type,
		Timestamp: event.Timestamp,
		RawData:   event.Data,
	}

	// Normalização específica por tipo de evento
	switch event.Type {
	case "cloudtrail":
		return p.normalizeCloudTrailEvent(normalized, event)
	case "vpc_flow_logs":
		return p.normalizeVPCFlowEvent(normalized, event)
	case "guardduty":
		return p.normalizeGuardDutyEvent(normalized, event)
	case "aws_config":
		return p.normalizeConfigEvent(normalized, event)
	default:
		return normalized, nil
	}
}

func (p *IngestPipeline) enrichEvent(event *NormalizedEvent) error {
	// Enriquecimento básico
	event.EnrichedData = make(map[string]interface{})

	// Adicionar informações geográficas se aplicável
	if ip, ok := event.RawData["sourceIPAddress"].(string); ok {
		geoInfo, err := p.lookupGeoIP(ip)
		if err == nil {
			event.EnrichedData["geo"] = geoInfo
		}
	}

	// Adicionar informações de asset se disponível
	if resource := event.Resource; resource != "" {
		assetInfo, err := p.lookupAsset(resource)
		if err == nil {
			event.EnrichedData["asset"] = assetInfo
		}
	}

	// Adicionar contexto de ameaças se aplicável
	if action := event.Action; action != "" {
		threatInfo, err := p.lookupThreatIntel(action)
		if err == nil {
			event.EnrichedData["threat"] = threatInfo
		}
	}

	return nil
}

func (p *IngestPipeline) indexEvent(event *NormalizedEvent) error {
	// Converter evento para JSON
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// Criar índice com base na data
	index := fmt.Sprintf("siem-events-%s", event.Timestamp.Format("2006.01.02"))

	// Indexar no Elasticsearch
	res, err := p.esClient.Index(
		index,
		bytes.NewReader(payload),
		p.esClient.Index.WithContext(p.ctx),
		p.esClient.Index.WithDocumentID(event.ID),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

func generateEventID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), uuid.New().String())
}