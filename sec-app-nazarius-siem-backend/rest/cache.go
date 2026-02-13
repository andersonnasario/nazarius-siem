package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
)

// CacheManager gerencia o cache Redis
type CacheManager struct {
	client *redis.Client
	ctx    context.Context
}

// NewCacheManager cria uma nova instância do cache manager
func NewCacheManager(redisURL string) (*CacheManager, error) {
	redisOptions := &redis.Options{
		Addr:     redisURL,
		Password: "",
		DB:       0,
	}
	
	// Enable TLS if REDIS_USE_TLS environment variable is set
	useTLS := false
	if tlsEnv := os.Getenv("REDIS_USE_TLS"); tlsEnv != "" {
		if tlsValue, err := strconv.ParseBool(tlsEnv); err == nil {
			useTLS = tlsValue
		}
	}
	
	if useTLS {
		redisOptions.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}
	
	client := redis.NewClient(redisOptions)

	ctx := context.Background()
	
	// Testa conexão
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("erro ao conectar ao Redis: %v", err)
	}

	return &CacheManager{
		client: client,
		ctx:    ctx,
	}, nil
}

// Set armazena um valor no cache
func (cm *CacheManager) Set(key string, value interface{}, ttl time.Duration) error {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("erro ao serializar dados: %v", err)
	}

	return cm.client.Set(cm.ctx, key, jsonData, ttl).Err()
}

// Get recupera um valor do cache
func (cm *CacheManager) Get(key string, dest interface{}) error {
	data, err := cm.client.Get(cm.ctx, key).Result()
	if err == redis.Nil {
		return fmt.Errorf("chave não encontrada no cache")
	}
	if err != nil {
		return fmt.Errorf("erro ao buscar do cache: %v", err)
	}

	return json.Unmarshal([]byte(data), dest)
}

// Delete remove uma chave do cache
func (cm *CacheManager) Delete(keys ...string) error {
	return cm.client.Del(cm.ctx, keys...).Err()
}

// Exists verifica se uma chave existe no cache
func (cm *CacheManager) Exists(key string) bool {
	result, err := cm.client.Exists(cm.ctx, key).Result()
	return err == nil && result > 0
}

// Invalidate invalida cache por padrão
func (cm *CacheManager) Invalidate(pattern string) error {
	iter := cm.client.Scan(cm.ctx, 0, pattern, 0).Iterator()
	var keys []string
	
	for iter.Next(cm.ctx) {
		keys = append(keys, iter.Val())
	}
	
	if err := iter.Err(); err != nil {
		return err
	}
	
	if len(keys) > 0 {
		return cm.client.Del(cm.ctx, keys...).Err()
	}
	
	return nil
}

// Cache keys constants
const (
	CacheDashboardStats     = "dashboard:stats"
	CacheIncidentStats      = "incident:stats"
	CacheMLAnalytics        = "ml:analytics"
	CacheSecurityEvents     = "security:events:%s"
	CacheUserSession        = "session:user:%s"
	CacheThreatIntel        = "threat:intel:%s"
	CacheAlertsActive       = "alerts:active"
	CacheMonitoringMetrics  = "monitoring:metrics"
)

// TTL constants
const (
	TTLShort  = 1 * time.Minute
	TTLMedium = 5 * time.Minute
	TTLLong   = 15 * time.Minute
	TTLHour   = 1 * time.Hour
	TTLDay    = 24 * time.Hour
)

// CacheDashboardStatsData cacheia estatísticas do dashboard
func (cm *CacheManager) CacheDashboardStatsData(stats interface{}) error {
	return cm.Set(CacheDashboardStats, stats, TTLMedium)
}

// GetCachedDashboardStats recupera estatísticas do dashboard do cache
func (cm *CacheManager) GetCachedDashboardStats(dest interface{}) error {
	return cm.Get(CacheDashboardStats, dest)
}

// CacheIncidentStatsData cacheia estatísticas de incidents
func (cm *CacheManager) CacheIncidentStatsData(stats interface{}) error {
	return cm.Set(CacheIncidentStats, stats, TTLMedium)
}

// GetCachedIncidentStats recupera estatísticas de incidents do cache
func (cm *CacheManager) GetCachedIncidentStats(dest interface{}) error {
	return cm.Get(CacheIncidentStats, dest)
}

// CacheMLAnalyticsData cacheia dados de ML analytics
func (cm *CacheManager) CacheMLAnalyticsData(data interface{}) error {
	return cm.Set(CacheMLAnalytics, data, TTLLong)
}

// GetCachedMLAnalytics recupera dados de ML analytics do cache
func (cm *CacheManager) GetCachedMLAnalytics(dest interface{}) error {
	return cm.Get(CacheMLAnalytics, dest)
}

// CacheSecurityEventsData cacheia eventos de segurança
func (cm *CacheManager) CacheSecurityEventsData(timeRange string, events interface{}) error {
	key := fmt.Sprintf(CacheSecurityEvents, timeRange)
	return cm.Set(key, events, TTLShort)
}

// GetCachedSecurityEvents recupera eventos de segurança do cache
func (cm *CacheManager) GetCachedSecurityEvents(timeRange string, dest interface{}) error {
	key := fmt.Sprintf(CacheSecurityEvents, timeRange)
	return cm.Get(key, dest)
}

// CacheUserSessionData cacheia dados de sessão do usuário
func (cm *CacheManager) CacheUserSessionData(userID string, session interface{}) error {
	key := fmt.Sprintf(CacheUserSession, userID)
	return cm.Set(key, session, TTLHour)
}

// GetCachedUserSession recupera dados de sessão do usuário do cache
func (cm *CacheManager) GetCachedUserSession(userID string, dest interface{}) error {
	key := fmt.Sprintf(CacheUserSession, userID)
	return cm.Get(key, dest)
}

// InvalidateDashboardCache invalida cache do dashboard
func (cm *CacheManager) InvalidateDashboardCache() error {
	return cm.Delete(CacheDashboardStats)
}

// InvalidateIncidentCache invalida cache de incidents
func (cm *CacheManager) InvalidateIncidentCache() error {
	return cm.Delete(CacheIncidentStats)
}

// InvalidateSecurityEventsCache invalida cache de eventos de segurança
func (cm *CacheManager) InvalidateSecurityEventsCache() error {
	return cm.Invalidate("security:events:*")
}

// InvalidateAllCache invalida todo o cache
func (cm *CacheManager) InvalidateAllCache() error {
	return cm.client.FlushDB(cm.ctx).Err()
}

// GetCacheStats retorna estatísticas do cache
func (cm *CacheManager) GetCacheStats() (map[string]interface{}, error) {
	info, err := cm.client.Info(cm.ctx, "stats").Result()
	if err != nil {
		return nil, err
	}

	dbSize, err := cm.client.DBSize(cm.ctx).Result()
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"db_size":       dbSize,
		"info":          info,
		"connected":     true,
		"hit_rate":      "N/A", // Calculado com métricas customizadas
		"memory_usage":  "N/A",
	}

	return stats, nil
}

// Incr incrementa um contador no cache
func (cm *CacheManager) Incr(key string) (int64, error) {
	return cm.client.Incr(cm.ctx, key).Result()
}

// IncrWithExpiry incrementa um contador com expiração
func (cm *CacheManager) IncrWithExpiry(key string, ttl time.Duration) (int64, error) {
	pipe := cm.client.Pipeline()
	incrCmd := pipe.Incr(cm.ctx, key)
	pipe.Expire(cm.ctx, key, ttl)
	
	_, err := pipe.Exec(cm.ctx)
	if err != nil {
		return 0, err
	}
	
	return incrCmd.Val(), nil
}

// GetMulti recupera múltiplas chaves do cache
func (cm *CacheManager) GetMulti(keys []string) ([]interface{}, error) {
	pipe := cm.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(keys))
	
	for i, key := range keys {
		cmds[i] = pipe.Get(cm.ctx, key)
	}
	
	_, err := pipe.Exec(cm.ctx)
	if err != nil && err != redis.Nil {
		return nil, err
	}
	
	results := make([]interface{}, len(keys))
	for i, cmd := range cmds {
		val, err := cmd.Result()
		if err == redis.Nil {
			results[i] = nil
			continue
		}
		if err != nil {
			return nil, err
		}
		results[i] = val
	}
	
	return results, nil
}

// SetMulti armazena múltiplas chaves no cache
func (cm *CacheManager) SetMulti(data map[string]interface{}, ttl time.Duration) error {
	pipe := cm.client.Pipeline()
	
	for key, value := range data {
		jsonData, err := json.Marshal(value)
		if err != nil {
			return err
		}
		pipe.Set(cm.ctx, key, jsonData, ttl)
	}
	
	_, err := pipe.Exec(cm.ctx)
	return err
}

// Lock cria um lock distribuído
func (cm *CacheManager) Lock(key string, ttl time.Duration) (bool, error) {
	return cm.client.SetNX(cm.ctx, "lock:"+key, "1", ttl).Result()
}

// Unlock remove um lock distribuído
func (cm *CacheManager) Unlock(key string) error {
	return cm.client.Del(cm.ctx, "lock:"+key).Err()
}

// Close fecha a conexão com o Redis
func (cm *CacheManager) Close() error {
	return cm.client.Close()
}

// Global cache manager instance
var globalCacheManager *CacheManager

// InitializeCache inicializa o cache manager global
func InitializeCache(redisURL string) error {
	cm, err := NewCacheManager(redisURL)
	if err != nil {
		return err
	}
	globalCacheManager = cm
	return nil
}

// GetCacheManager retorna a instância global do cache manager
func GetCacheManager() *CacheManager {
	return globalCacheManager
}

