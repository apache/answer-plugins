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

package es_vector_search

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer-plugins/vector-search-elasticsearch/i18n"
	"github.com/apache/answer/plugin"
	"github.com/olivere/elastic/v7"
	"github.com/segmentfault/pacman/log"
)

//go:embed info.yaml
var Info embed.FS

const (
	indexName = "answer_vector"
)

// VectorSearchEngine implements plugin.VectorSearch.
type VectorSearchEngine struct {
	Config              *VectorSearchConfig
	client              *elastic.Client
	syncer              plugin.VectorSearchSyncer
	syncing             bool
	lock                sync.Mutex
	embeddingDimensions int // auto-detected from embedding model
}

// VectorSearchConfig holds all plugin configuration.
type VectorSearchConfig struct {
	Endpoints           string  `json:"endpoints"`
	Username            string  `json:"username"`
	Password            string  `json:"password"`
	APIHost             string  `json:"api_host"`
	APIKey              string  `json:"api_key"`
	EmbeddingModel      string  `json:"embedding_model"`
	EmbeddingLevel      string  `json:"embedding_level"`
	SimilarityThreshold float64 `json:"similarity_threshold"`
}

func init() {
	plugin.Register(&VectorSearchEngine{
		Config: &VectorSearchConfig{},
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

// Description returns metadata about this vector search engine.
func (e *VectorSearchEngine) Description() plugin.VectorSearchDesc {
	return plugin.VectorSearchDesc{
		Icon: "",
		Link: "https://www.elastic.co/guide/en/elasticsearch/reference/current/dense-vector.html",
	}
}

// RegisterSyncer stores the syncer and triggers a full sync.
func (e *VectorSearchEngine) RegisterSyncer(ctx context.Context, syncer plugin.VectorSearchSyncer) {
	e.syncer = syncer
	if e.client != nil {
		e.sync()
	}
}

// SearchSimilar performs a kNN search using dense_vector cosine similarity.
func (e *VectorSearchEngine) SearchSimilar(ctx context.Context, query string, topK int) ([]plugin.VectorSearchResult, error) {
	if e.client == nil {
		return nil, fmt.Errorf("elasticsearch client not initialized")
	}
	if topK <= 0 {
		topK = 10
	}

	// Generate embedding for the query text.
	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.APIHost, e.Config.APIKey, e.Config.EmbeddingModel, query)
	if err != nil {
		return nil, fmt.Errorf("generate query embedding: %w", err)
	}

	// Build kNN search body.
	embeddingFloats := make([]float64, len(embedding))
	for i, v := range embedding {
		embeddingFloats[i] = float64(v)
	}
	knnQuery := map[string]interface{}{
		"knn": map[string]interface{}{
			"field":          "embedding",
			"query_vector":   embeddingFloats,
			"k":              topK,
			"num_candidates": topK * 4,
		},
		"size": topK,
		"_source": []string{
			"object_id", "object_type", "metadata", "score",
		},
	}
	knnBody, _ := json.Marshal(knnQuery)

	res, err := e.client.PerformRequest(ctx, elastic.PerformRequestOptions{
		Method: "POST",
		Path:   fmt.Sprintf("/%s/_search", indexName),
		Body:   string(knnBody),
	})
	if err != nil {
		return nil, fmt.Errorf("kNN search failed: %w", err)
	}

	var searchResp elastic.SearchResult
	if err := json.Unmarshal(res.Body, &searchResp); err != nil {
		return nil, fmt.Errorf("parse kNN response: %w", err)
	}

	results := make([]plugin.VectorSearchResult, 0, len(searchResp.Hits.Hits))
	for _, hit := range searchResp.Hits.Hits {
		var doc map[string]interface{}
		if err := json.Unmarshal(hit.Source, &doc); err != nil {
			log.Warnf("unmarshal hit: %v", err)
			continue
		}
		score := 0.0
		if hit.Score != nil {
			score = float64(*hit.Score)
		}
		if e.Config.SimilarityThreshold > 0 && score < e.Config.SimilarityThreshold {
			continue
		}
		objectID, _ := doc["object_id"].(string)
		objectType, _ := doc["object_type"].(string)
		metadata, _ := doc["metadata"].(string)
		results = append(results, plugin.VectorSearchResult{
			ObjectID:   objectID,
			ObjectType: objectType,
			Metadata:   metadata,
			Score:      score,
		})
	}
	return results, nil
}

// UpdateContent upserts a single document.
func (e *VectorSearchEngine) UpdateContent(ctx context.Context, content *plugin.VectorSearchContent) error {
	if e.client == nil {
		return fmt.Errorf("elasticsearch client not initialized")
	}

	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.APIHost, e.Config.APIKey, e.Config.EmbeddingModel, content.Content)
	if err != nil {
		return fmt.Errorf("generate embedding for %s: %w", content.ObjectID, err)
	}

	doc := map[string]interface{}{
		"object_id":   content.ObjectID,
		"object_type": content.ObjectType,
		"title":       content.Title,
		"content":     content.Content,
		"metadata":    content.Metadata,
		"embedding":   embedding,
	}
	_, err = e.client.Index().
		Index(indexName).
		Id(content.ObjectID).
		BodyJson(doc).
		Do(ctx)
	if err != nil {
		return fmt.Errorf("index document %s: %w", content.ObjectID, err)
	}
	return nil
}

// DeleteContent removes a document by object ID.
func (e *VectorSearchEngine) DeleteContent(ctx context.Context, objectID string) error {
	if e.client == nil {
		return fmt.Errorf("elasticsearch client not initialized")
	}
	_, err := e.client.Delete().
		Index(indexName).
		Id(objectID).
		Do(ctx)
	if err != nil {
		if elastic.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("delete document %s: %w", objectID, err)
	}
	return nil
}

// ConfigFields returns the plugin configuration form fields.
func (e *VectorSearchEngine) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "endpoints",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigEndpointsTitle),
			Description: plugin.MakeTranslator(i18n.ConfigEndpointsDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: e.Config.Endpoints,
		},
		{
			Name:        "username",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigUsernameTitle),
			Description: plugin.MakeTranslator(i18n.ConfigUsernameDescription),
			Required:    false,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: e.Config.Username,
		},
		{
			Name:        "password",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigPasswordTitle),
			Description: plugin.MakeTranslator(i18n.ConfigPasswordDescription),
			Required:    false,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypePassword,
			},
			Value: e.Config.Password,
		},
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

// ConfigReceiver applies configuration from the admin UI.
func (e *VectorSearchEngine) ConfigReceiver(config []byte) error {
	// Pre-process: convert string numbers to actual numbers before unmarshalling,
	// because the admin UI sends all form values as strings.
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

	if !plugin.StatusManager.IsEnabled("es_vector_search") {
		log.Debugf("es-vector: plugin not active, skipping initialization")
		return nil
	}

	// Auto-detect embedding dimensions by generating a probe embedding.
	log.Debugf("es-vector: detecting embedding dimensions via probe call")
	probeEmbedding, err := plugin.GenerateEmbedding(context.Background(), conf.APIHost, conf.APIKey, conf.EmbeddingModel, "dimension probe")
	if err != nil {
		return fmt.Errorf("detect embedding dimensions: %w", err)
	}
	e.embeddingDimensions = len(probeEmbedding)
	log.Infof("es-vector: auto-detected embedding dimensions=%d for model=%s", e.embeddingDimensions, conf.EmbeddingModel)

	log.Debugf("es-vector: initializing client: %s", conf.Endpoints)

	endpoints := strings.Split(conf.Endpoints, ",")
	opts := []elastic.ClientOptionFunc{
		elastic.SetURL(endpoints...),
		elastic.SetSniff(false),
	}
	if conf.Username != "" && conf.Password != "" {
		opts = append(opts, elastic.SetBasicAuth(conf.Username, conf.Password))
	}

	client, err := elastic.NewClient(opts...)
	if err != nil {
		return fmt.Errorf("create es client: %w", err)
	}
	e.client = client

	// Create/ensure the index with dense_vector mapping.
	if err := e.ensureIndex(context.Background()); err != nil {
		return fmt.Errorf("ensure index: %w", err)
	}

	return nil
}

// ensureIndex creates the ES index with dense_vector mapping if it doesn't exist.
func (e *VectorSearchEngine) ensureIndex(ctx context.Context) error {
	dims := e.embeddingDimensions
	if dims <= 0 {
		dims = 1536
	}

	exists, err := e.client.IndexExists(indexName).Do(ctx)
	if err != nil {
		return err
	}

	if exists {
		// If the existing index's embedding dimensions differ from the
		// configured ones (e.g. the embedding model changed), delete it so it
		// can be recreated with the new dimensions.
		existingDims, err := e.indexEmbeddingDims(ctx)
		if err != nil {
			return fmt.Errorf("get index mapping: %w", err)
		}
		if existingDims > 0 && existingDims != dims {
			log.Warnf("es-vector: dimensions changed from %d to %d, recreating index", existingDims, dims)
			if _, err := e.client.DeleteIndex(indexName).Do(ctx); err != nil {
				return fmt.Errorf("delete index for dimension change: %w", err)
			}
			exists = false
		}
	}

	if exists {
		return nil
	}

	mapping := fmt.Sprintf(`{
		"mappings": {
			"properties": {
				"object_id":   { "type": "keyword" },
				"object_type": { "type": "keyword" },
				"title":       { "type": "text" },
				"content":     { "type": "text" },
				"metadata":    { "type": "text", "index": false },
				"embedding": {
					"type": "dense_vector",
					"dims": %d,
					"index": true,
					"similarity": "cosine"
				}
			}
		}
	}`, dims)

	_, err = e.client.CreateIndex(indexName).Body(mapping).Do(ctx)
	return err
}

// indexEmbeddingDims returns the configured `dims` of the embedding field in the
// existing index mapping, or 0 if it cannot be determined.
func (e *VectorSearchEngine) indexEmbeddingDims(ctx context.Context) (int, error) {
	m, err := e.client.GetMapping().Index(indexName).Do(ctx)
	if err != nil {
		return 0, err
	}
	// Response shape:
	// { "<index>": { "mappings": { "properties": { "embedding": { "dims": N } } } } }
	idx, ok := m[indexName].(map[string]interface{})
	if !ok {
		return 0, nil
	}
	mappings, ok := idx["mappings"].(map[string]interface{})
	if !ok {
		return 0, nil
	}
	props, ok := mappings["properties"].(map[string]interface{})
	if !ok {
		return 0, nil
	}
	embedding, ok := props["embedding"].(map[string]interface{})
	if !ok {
		return 0, nil
	}
	dims, ok := embedding["dims"].(float64)
	if !ok {
		return 0, nil
	}
	return int(dims), nil
}

