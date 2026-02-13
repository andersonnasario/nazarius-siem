package mocks

import (
	"fmt"
	"time"
)

// MockRedisClient simula um cliente Redis para testes
type MockRedisClient struct {
	Store  map[string]string
	Expiry map[string]time.Time
	Lists  map[string][]string
	Sets   map[string]map[string]bool
	Hashes map[string]map[string]string
}

// NewMockRedisClient cria um novo mock do Redis
func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		Store:  make(map[string]string),
		Expiry: make(map[string]time.Time),
		Lists:  make(map[string][]string),
		Sets:   make(map[string]map[string]bool),
		Hashes: make(map[string]map[string]string),
	}
}

// Set simula SET no Redis
func (m *MockRedisClient) Set(key, value string, expiration time.Duration) error {
	if key == "" {
		return fmt.Errorf("key não pode ser vazio")
	}

	m.Store[key] = value
	if expiration > 0 {
		m.Expiry[key] = time.Now().Add(expiration)
	}
	return nil
}

// Get simula GET no Redis
func (m *MockRedisClient) Get(key string) (string, error) {
	// Verifica expiração
	if expiry, exists := m.Expiry[key]; exists {
		if time.Now().After(expiry) {
			delete(m.Store, key)
			delete(m.Expiry, key)
			return "", fmt.Errorf("key não encontrada ou expirada")
		}
	}

	value, exists := m.Store[key]
	if !exists {
		return "", fmt.Errorf("key não encontrada")
	}
	return value, nil
}

// Delete simula DEL no Redis
func (m *MockRedisClient) Delete(keys ...string) error {
	for _, key := range keys {
		delete(m.Store, key)
		delete(m.Expiry, key)
	}
	return nil
}

// Exists simula EXISTS no Redis
func (m *MockRedisClient) Exists(key string) (bool, error) {
	_, exists := m.Store[key]
	return exists, nil
}

// Expire simula EXPIRE no Redis
func (m *MockRedisClient) Expire(key string, expiration time.Duration) error {
	if _, exists := m.Store[key]; !exists {
		return fmt.Errorf("key não encontrada")
	}
	m.Expiry[key] = time.Now().Add(expiration)
	return nil
}

// TTL simula TTL no Redis
func (m *MockRedisClient) TTL(key string) (time.Duration, error) {
	expiry, exists := m.Expiry[key]
	if !exists {
		return -1, nil // -1 indica sem expiração
	}

	remaining := time.Until(expiry)
	if remaining < 0 {
		return -2, nil // -2 indica expirado
	}
	return remaining, nil
}

// Incr simula INCR no Redis
func (m *MockRedisClient) Incr(key string) (int64, error) {
	value, exists := m.Store[key]
	var intValue int64 = 0

	if exists {
		fmt.Sscanf(value, "%d", &intValue)
	}

	intValue++
	m.Store[key] = fmt.Sprintf("%d", intValue)
	return intValue, nil
}

// Decr simula DECR no Redis
func (m *MockRedisClient) Decr(key string) (int64, error) {
	value, exists := m.Store[key]
	var intValue int64 = 0

	if exists {
		fmt.Sscanf(value, "%d", &intValue)
	}

	intValue--
	m.Store[key] = fmt.Sprintf("%d", intValue)
	return intValue, nil
}

// LPush simula LPUSH no Redis (adiciona à esquerda da lista)
func (m *MockRedisClient) LPush(key string, values ...string) error {
	if m.Lists[key] == nil {
		m.Lists[key] = make([]string, 0)
	}

	// Adiciona elementos no início da lista
	for i := len(values) - 1; i >= 0; i-- {
		m.Lists[key] = append([]string{values[i]}, m.Lists[key]...)
	}
	return nil
}

// RPush simula RPUSH no Redis (adiciona à direita da lista)
func (m *MockRedisClient) RPush(key string, values ...string) error {
	if m.Lists[key] == nil {
		m.Lists[key] = make([]string, 0)
	}

	m.Lists[key] = append(m.Lists[key], values...)
	return nil
}

// LPop simula LPOP no Redis (remove e retorna da esquerda)
func (m *MockRedisClient) LPop(key string) (string, error) {
	list, exists := m.Lists[key]
	if !exists || len(list) == 0 {
		return "", fmt.Errorf("lista vazia ou não existe")
	}

	value := list[0]
	m.Lists[key] = list[1:]
	return value, nil
}

// RPop simula RPOP no Redis (remove e retorna da direita)
func (m *MockRedisClient) RPop(key string) (string, error) {
	list, exists := m.Lists[key]
	if !exists || len(list) == 0 {
		return "", fmt.Errorf("lista vazia ou não existe")
	}

	value := list[len(list)-1]
	m.Lists[key] = list[:len(list)-1]
	return value, nil
}

// LLen simula LLEN no Redis (retorna tamanho da lista)
func (m *MockRedisClient) LLen(key string) (int64, error) {
	list, exists := m.Lists[key]
	if !exists {
		return 0, nil
	}
	return int64(len(list)), nil
}

// LRange simula LRANGE no Redis
func (m *MockRedisClient) LRange(key string, start, stop int64) ([]string, error) {
	list, exists := m.Lists[key]
	if !exists {
		return []string{}, nil
	}

	length := int64(len(list))
	if start < 0 {
		start = length + start
	}
	if stop < 0 {
		stop = length + stop
	}

	if start < 0 {
		start = 0
	}
	if stop >= length {
		stop = length - 1
	}

	if start > stop {
		return []string{}, nil
	}

	return list[start : stop+1], nil
}

// SAdd simula SADD no Redis (adiciona a um set)
func (m *MockRedisClient) SAdd(key string, members ...string) error {
	if m.Sets[key] == nil {
		m.Sets[key] = make(map[string]bool)
	}

	for _, member := range members {
		m.Sets[key][member] = true
	}
	return nil
}

// SMembers simula SMEMBERS no Redis (retorna membros do set)
func (m *MockRedisClient) SMembers(key string) ([]string, error) {
	set, exists := m.Sets[key]
	if !exists {
		return []string{}, nil
	}

	members := make([]string, 0, len(set))
	for member := range set {
		members = append(members, member)
	}
	return members, nil
}

// SIsMember simula SISMEMBER no Redis
func (m *MockRedisClient) SIsMember(key, member string) (bool, error) {
	set, exists := m.Sets[key]
	if !exists {
		return false, nil
	}
	return set[member], nil
}

// SCard simula SCARD no Redis (retorna tamanho do set)
func (m *MockRedisClient) SCard(key string) (int64, error) {
	set, exists := m.Sets[key]
	if !exists {
		return 0, nil
	}
	return int64(len(set)), nil
}

// HSet simula HSET no Redis (set em hash)
func (m *MockRedisClient) HSet(key, field, value string) error {
	if m.Hashes[key] == nil {
		m.Hashes[key] = make(map[string]string)
	}
	m.Hashes[key][field] = value
	return nil
}

// HGet simula HGET no Redis (get de hash)
func (m *MockRedisClient) HGet(key, field string) (string, error) {
	hash, exists := m.Hashes[key]
	if !exists {
		return "", fmt.Errorf("hash não encontrado")
	}

	value, exists := hash[field]
	if !exists {
		return "", fmt.Errorf("field não encontrado")
	}
	return value, nil
}

// HGetAll simula HGETALL no Redis
func (m *MockRedisClient) HGetAll(key string) (map[string]string, error) {
	hash, exists := m.Hashes[key]
	if !exists {
		return make(map[string]string), nil
	}

	// Retorna uma cópia
	result := make(map[string]string)
	for k, v := range hash {
		result[k] = v
	}
	return result, nil
}

// HDel simula HDEL no Redis
func (m *MockRedisClient) HDel(key string, fields ...string) error {
	hash, exists := m.Hashes[key]
	if !exists {
		return nil
	}

	for _, field := range fields {
		delete(hash, field)
	}
	return nil
}

// FlushAll simula FLUSHALL no Redis (limpa tudo)
func (m *MockRedisClient) FlushAll() error {
	m.Store = make(map[string]string)
	m.Expiry = make(map[string]time.Time)
	m.Lists = make(map[string][]string)
	m.Sets = make(map[string]map[string]bool)
	m.Hashes = make(map[string]map[string]string)
	return nil
}

// Ping simula PING no Redis
func (m *MockRedisClient) Ping() error {
	return nil
}

// Keys simula KEYS no Redis (retorna keys que correspondem ao pattern)
func (m *MockRedisClient) Keys(pattern string) ([]string, error) {
	keys := make([]string, 0)
	for key := range m.Store {
		// Simulação simplificada - retorna todas as keys
		keys = append(keys, key)
	}
	return keys, nil
}

// Reset limpa todos os dados do mock
func (m *MockRedisClient) Reset() {
	m.FlushAll()
}

