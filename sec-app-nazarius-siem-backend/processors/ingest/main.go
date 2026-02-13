package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/segmentio/kafka-go"
)

type IngestPipeline struct {
	consumers map[string]*kafka.Reader
	esClient  *elasticsearch.Client
	ctx       context.Context
	cancel    context.CancelFunc
}

// Configuração dos tópicos Kafka a serem consumidos
var topics = []string{
	"siem-aws-cloudtrail",
	"siem-aws-vpc-flow",
	"siem-aws-guardduty",
	"siem-aws-config",
}

func NewIngestPipeline() (*IngestPipeline, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Inicializar cliente Elasticsearch
	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{"http://localhost:9200"},
	})
	if err != nil {
		return nil, err
	}

	// Criar consumidores Kafka para cada tópico
	consumers := make(map[string]*kafka.Reader)
	for _, topic := range topics {
		consumers[topic] = kafka.NewReader(kafka.ReaderConfig{
			Brokers:     []string{"localhost:9092"},
			Topic:       topic,
			GroupID:     "siem-ingest-group",
			StartOffset: kafka.FirstOffset,
		})
	}

	return &IngestPipeline{
		consumers: consumers,
		esClient:  es,
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

func (p *IngestPipeline) Start() error {
	var wg sync.WaitGroup

	// Iniciar consumidores para cada tópico
	for topic, consumer := range p.consumers {
		wg.Add(1)
		go p.processMessages(topic, consumer, &wg)
	}

	// Aguardar sinal de interrupção
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Encerrar graciosamente
	p.cancel()
	wg.Wait()

	// Fechar consumidores
	for _, consumer := range p.consumers {
		if err := consumer.Close(); err != nil {
			log.Printf("Erro ao fechar consumidor Kafka: %v", err)
		}
	}

	return nil
}

func main() {
	pipeline, err := NewIngestPipeline()
	if err != nil {
		log.Fatalf("Erro ao criar pipeline de ingestão: %v", err)
	}

	if err := pipeline.Start(); err != nil {
		log.Fatalf("Erro ao executar pipeline de ingestão: %v", err)
	}
}