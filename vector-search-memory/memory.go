/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package memory_vector_search

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"sync"

	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer-plugins/vector-search-memory/i18n"
	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
)

//go:embed info.yaml
var Info embed.FS

type document struct {
	objectID   string
	objectType string
	title      string
	content    string
	metadata   string
	embedding  []float32
}

// VectorSearchEngine implements plugin.VectorSearch using an in-memory store.
type VectorSearchEngine struct {
	Config              *VectorSearchConfig
	docs                map[string]*document
	mu                  sync.RWMutex
	syncer              plugin.VectorSearchSyncer
	syncing             bool
	lock                sync.Mutex
	embeddingDimensions int
	configured          bool
}

// VectorSearchConfig holds all plugin configuration.
type VectorSearchConfig struct {
	APIHost             string  `json:"api_host"`
	APIKey              string  `json:"api_key"`
	EmbeddingModel      string  `json:"embedding_model"`
	EmbeddingLevel      string  `json:"embedding_level"`
	SimilarityThreshold float64 `json:"similarity_threshold"`
}

func init() {
	plugin.Register(&VectorSearchEngine{
		Config: &VectorSearchConfig{},
		docs:   make(map[string]*document),
		lock:   sync.Mutex{},
	})
}

func (e *VectorSearchEngine) Info() plugin.Info {
	info := &util.Info{}
	info.GetInfo(Info)

	return plugin.Info{
		Name:        plugin.MakeTranslator(i18n.InfoName),
		SlugName:    info.SlugName,
		Description: plugin.MakeTranslator(i18n.InfoDescription),
		Author:      info.Author,
		Version:     info.Version,
		Link:        info.Link,
	}
}

func (e *VectorSearchEngine) Description() plugin.VectorSearchDesc {
	return plugin.VectorSearchDesc{
		Icon: "",
		Link: "",
	}
}

func (e *VectorSearchEngine) RegisterSyncer(ctx context.Context, syncer plugin.VectorSearchSyncer) {
	log.Debugf("memory: RegisterSyncer called, configured=%v", e.configured)
	e.syncer = syncer
	if e.configured {
		e.sync()
	}
}

func (e *VectorSearchEngine) SearchSimilar(ctx context.Context, query string, topK int) ([]plugin.VectorSearchResult, error) {
	if !e.configured {
		return nil, fmt.Errorf("memory: not initialized")
	}
	if topK <= 0 {
		topK = 10
	}

	log.Debugf("memory: SearchSimilar query=%q topK=%d", query, topK)

	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.APIHost, e.Config.APIKey, e.Config.EmbeddingModel, query)
	if err != nil {
		return nil, fmt.Errorf("generate query embedding: %w", err)
	}

	log.Debugf("memory: search embedding generated, dimensions=%d", len(embedding))

	e.mu.RLock()
	type scored struct {
		doc   *document
		score float64
	}
	candidates := make([]scored, 0, len(e.docs))
	for _, doc := range e.docs {
		score := cosineSimilarity(embedding, doc.embedding)
		if e.Config.SimilarityThreshold > 0 && score < e.Config.SimilarityThreshold {
			continue
		}
		candidates = append(candidates, scored{doc: doc, score: score})
	}
	e.mu.RUnlock()

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	if len(candidates) > topK {
		candidates = candidates[:topK]
	}

	results := make([]plugin.VectorSearchResult, 0, len(candidates))
	for _, c := range candidates {
		results = append(results, plugin.VectorSearchResult{
			ObjectID:   c.doc.objectID,
			ObjectType: c.doc.objectType,
			Metadata:   c.doc.metadata,
			Score:      c.score,
		})
	}

	log.Debugf("memory: SearchSimilar returning %d results", len(results))
	return results, nil
}

func (e *VectorSearchEngine) UpdateContent(ctx context.Context, content *plugin.VectorSearchContent) error {
	if !e.configured {
		return fmt.Errorf("memory: not initialized")
	}

	log.Debugf("memory: UpdateContent objectID=%s objectType=%s", content.ObjectID, content.ObjectType)

	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.APIHost, e.Config.APIKey, e.Config.EmbeddingModel, content.Content)
	if err != nil {
		return fmt.Errorf("generate embedding for %s: %w", content.ObjectID, err)
	}

	log.Debugf("memory: embedding generated for %s, dimensions=%d", content.ObjectID, len(embedding))

	e.mu.Lock()
	e.docs[content.ObjectID] = &document{
		objectID:   content.ObjectID,
		objectType: content.ObjectType,
		title:      content.Title,
		content:    content.Content,
		metadata:   content.Metadata,
		embedding:  embedding,
	}
	e.mu.Unlock()

	log.Debugf("memory: upserted document %s successfully (total docs=%d)", content.ObjectID, len(e.docs))
	return nil
}

func (e *VectorSearchEngine) DeleteContent(ctx context.Context, objectID string) error {
	if !e.configured {
		return fmt.Errorf("memory: not initialized")
	}

	log.Debugf("memory: DeleteContent objectID=%s", objectID)

	e.mu.Lock()
	delete(e.docs, objectID)
	e.mu.Unlock()

	log.Debugf("memory: deleted document %s", objectID)
	return nil
}

func (e *VectorSearchEngine) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "api_host",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigAPIHostTitle),
			Description: plugin.MakeTranslator(i18n.ConfigAPIHostDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: e.Config.APIHost,
		},
		{
			Name:        "api_key",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigAPIKeyTitle),
			Description: plugin.MakeTranslator(i18n.ConfigAPIKeyDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypePassword,
			},
			Value: e.Config.APIKey,
		},
		{
			Name:        "embedding_model",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigEmbeddingModelTitle),
			Description: plugin.MakeTranslator(i18n.ConfigEmbeddingModelDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: e.Config.EmbeddingModel,
		},
		{
			Name:        "embedding_level",
			Type:        plugin.ConfigTypeSelect,
			Title:       plugin.MakeTranslator(i18n.ConfigEmbeddingLevelTitle),
			Description: plugin.MakeTranslator(i18n.ConfigEmbeddingLevelDescription),
			Required:    true,
			Options: []plugin.ConfigFieldOption{
				{Label: plugin.MakeTranslator(i18n.ConfigEmbeddingLevelOptionQuestion), Value: "question"},
				{Label: plugin.MakeTranslator(i18n.ConfigEmbeddingLevelOptionAnswer), Value: "answer"},
			},
			Value: e.Config.EmbeddingLevel,
		},
		{
			Name:        "similarity_threshold",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigSimilarityThresholdTitle),
			Description: plugin.MakeTranslator(i18n.ConfigSimilarityThresholdDescription),
			Required:    false,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: fmt.Sprintf("%.2f", e.Config.SimilarityThreshold),
		},
	}
}

func (e *VectorSearchEngine) ConfigReceiver(config []byte) error {
	log.Debugf("memory: ConfigReceiver called")

	var raw map[string]interface{}
	if err := json.Unmarshal(config, &raw); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}
	if threshStr, ok := raw["similarity_threshold"].(string); ok {
		if thresh, err := strconv.ParseFloat(threshStr, 64); err == nil {
			raw["similarity_threshold"] = thresh
		}
	}
	fixed, _ := json.Marshal(raw)

	conf := &VectorSearchConfig{}
	if err := json.Unmarshal(fixed, conf); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}

	e.Config = conf

	log.Debugf("memory: config parsed: model=%s level=%s threshold=%.2f",
		conf.EmbeddingModel, conf.EmbeddingLevel, conf.SimilarityThreshold)

	if !plugin.StatusManager.IsEnabled("memory_vector_search") {
		log.Debugf("memory: plugin not active, skipping initialization")
		return nil
	}

	// Auto-detect embedding dimensions.
	log.Debugf("memory: detecting embedding dimensions via probe call")
	probeEmbedding, err := plugin.GenerateEmbedding(context.Background(), conf.APIHost, conf.APIKey, conf.EmbeddingModel, "dimension probe")
	if err != nil {
		return fmt.Errorf("detect embedding dimensions: %w", err)
	}
	e.embeddingDimensions = len(probeEmbedding)
	log.Infof("memory: auto-detected embedding dimensions=%d for model=%s", e.embeddingDimensions, conf.EmbeddingModel)

	// Clear existing documents since model may have changed.
	e.mu.Lock()
	e.docs = make(map[string]*document)
	e.mu.Unlock()

	e.configured = true

	log.Debugf("memory: ConfigReceiver completed successfully")
	return nil
}

// cosineSimilarity computes the cosine similarity between two vectors.
func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		ai, bi := float64(a[i]), float64(b[i])
		dot += ai * bi
		normA += ai * ai
		normB += bi * bi
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}
