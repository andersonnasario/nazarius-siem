package main

import (
	"compress/gzip"
	"io"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// gzipWriterPool é um pool de gzip writers para reutilização
var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		return gzip.NewWriter(io.Discard)
	},
}

// gzipWriter wrapper para gin.ResponseWriter com suporte a gzip
type gzipWriter struct {
	gin.ResponseWriter
	writer *gzip.Writer
}

// Write implementa io.Writer
func (g *gzipWriter) Write(data []byte) (int, error) {
	return g.writer.Write(data)
}

// WriteString implementa io.StringWriter
func (g *gzipWriter) WriteString(s string) (int, error) {
	return g.writer.Write([]byte(s))
}

// CompressionMiddleware adiciona compressão gzip às respostas
func CompressionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Verifica se o cliente suporta gzip
		if !shouldCompress(c) {
			c.Next()
			return
		}

		// Pega um writer do pool
		gz := gzipWriterPool.Get().(*gzip.Writer)
		defer gzipWriterPool.Put(gz)

		gz.Reset(c.Writer)
		defer gz.Close()

		// Configura headers
		c.Header("Content-Encoding", "gzip")
		c.Header("Vary", "Accept-Encoding")

		// Wrapper do writer
		gzWriter := &gzipWriter{
			ResponseWriter: c.Writer,
			writer:         gz,
		}
		c.Writer = gzWriter

		c.Next()

		// Força flush do buffer
		gz.Flush()
	}
}

// shouldCompress determina se a resposta deve ser comprimida
func shouldCompress(c *gin.Context) bool {
	// Verifica se cliente aceita gzip
	if !strings.Contains(c.GetHeader("Accept-Encoding"), "gzip") {
		return false
	}

	// Não comprimir se já estiver comprimido
	if c.GetHeader("Content-Encoding") != "" {
		return false
	}

	// Não comprimir WebSocket
	if strings.Contains(strings.ToLower(c.GetHeader("Connection")), "upgrade") &&
		strings.ToLower(c.GetHeader("Upgrade")) == "websocket" {
		return false
	}

	// Não comprimir event-stream (SSE)
	if strings.Contains(c.GetHeader("Content-Type"), "text/event-stream") {
		return false
	}

	// Não comprimir imagens já comprimidas
	contentType := c.GetHeader("Content-Type")
	skipTypes := []string{
		"image/jpeg",
		"image/png",
		"image/gif",
		"video/",
		"audio/",
		"application/zip",
		"application/gzip",
	}

	for _, skipType := range skipTypes {
		if strings.Contains(contentType, skipType) {
			return false
		}
	}

	return true
}

// ConditionalCompressionMiddleware comprime apenas respostas maiores que um threshold
func ConditionalCompressionMiddleware(minSize int) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Buffer para capturar a resposta
		blw := &bodyLogWriter{body: make([]byte, 0), ResponseWriter: c.Writer}
		c.Writer = blw

		c.Next()

		// Se a resposta for pequena, não comprimir
		if len(blw.body) < minSize || !shouldCompress(c) {
			c.Writer.Write(blw.body)
			return
		}

		// Comprimir resposta
		gz := gzipWriterPool.Get().(*gzip.Writer)
		defer gzipWriterPool.Put(gz)

		gz.Reset(blw.ResponseWriter)
		defer gz.Close()

		c.Header("Content-Encoding", "gzip")
		c.Header("Vary", "Accept-Encoding")

		gz.Write(blw.body)
		gz.Flush()
	}
}

// bodyLogWriter captura o body da resposta
type bodyLogWriter struct {
	gin.ResponseWriter
	body []byte
}

func (w *bodyLogWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}

func (w *bodyLogWriter) WriteString(s string) (int, error) {
	w.body = append(w.body, []byte(s)...)
	return len(s), nil
}

// BrotliCompressionMiddleware adiciona compressão Brotli (mais eficiente que gzip)
// Note: Requer biblioteca externa go-brotli
func BrotliCompressionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Por simplicidade, usaremos gzip
		// Em produção, pode-se adicionar suporte a Brotli
		CompressionMiddleware()(c)
	}
}

// CompressionStats armazena estatísticas de compressão
type CompressionStats struct {
	TotalRequests     int64
	CompressedRequests int64
	BytesSaved        int64
	CompressionRatio  float64
}

var compressionStats = &CompressionStats{}
var statsLock sync.RWMutex

// GetCompressionStats retorna estatísticas de compressão
func GetCompressionStats() CompressionStats {
	statsLock.RLock()
	defer statsLock.RUnlock()
	
	stats := *compressionStats
	if stats.CompressedRequests > 0 {
		stats.CompressionRatio = float64(stats.BytesSaved) / float64(stats.CompressedRequests)
	}
	
	return stats
}

// TrackCompressionStats middleware para rastrear estatísticas de compressão
func TrackCompressionStats() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Captura tamanho original
		blw := &bodyLogWriter{body: make([]byte, 0), ResponseWriter: c.Writer}
		c.Writer = blw

		c.Next()

		originalSize := len(blw.body)
		
		statsLock.Lock()
		compressionStats.TotalRequests++
		
		// Se foi comprimido
		if c.GetHeader("Content-Encoding") == "gzip" {
			compressionStats.CompressedRequests++
			// Estimativa de economia (gzip geralmente consegue 60-80% de compressão)
			compressionStats.BytesSaved += int64(originalSize * 70 / 100)
		}
		statsLock.Unlock()

		// Escreve resposta
		c.Writer = blw.ResponseWriter
		c.Writer.Write(blw.body)
	}
}

// ResetCompressionStats reseta as estatísticas de compressão
func ResetCompressionStats() {
	statsLock.Lock()
	defer statsLock.Unlock()
	compressionStats = &CompressionStats{}
}

