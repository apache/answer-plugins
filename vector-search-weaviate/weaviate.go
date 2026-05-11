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

package weaviate_vector_search

import (
	"context"
	"crypto/sha1"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer-plugins/vector-search-weaviate/i18n"
	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
	"github.com/weaviate/weaviate-go-client/v4/weaviate"
	"github.com/weaviate/weaviate-go-client/v4/weaviate/auth"
	"github.com/weaviate/weaviate-go-client/v4/weaviate/graphql"
	"github.com/weaviate/weaviate/entities/models"
)

//go:embed info.yaml
var Info embed.FS

const (
	className = "AnswerVector"
)

// VectorSearchEngine implements plugin.VectorSearch using Weaviate.
type VectorSearchEngine struct {
	Config  *VectorSearchConfig
	client  *weaviate.Client
	syncer  plugin.VectorSearchSyncer
	syncing bool
	lock    sync.Mutex
}

// VectorSearchConfig holds all plugin configuration.
type VectorSearchConfig struct {
	Endpoint            string  `json:"endpoint"`
	APIKey              string  `json:"api_key"`
	EmbeddingAPIHost    string  `json:"embedding_api_host"`
	EmbeddingAPIKey     string  `json:"embedding_api_key"`
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
		Link: "https://weaviate.io/developers/weaviate",
	}
}

// RegisterSyncer stores the syncer and triggers a full sync.
func (e *VectorSearchEngine) RegisterSyncer(ctx context.Context, syncer plugin.VectorSearchSyncer) {
	e.syncer = syncer
	if e.client != nil {
		e.sync()
	}
}

// SearchSimilar performs a nearVector search in Weaviate.
func (e *VectorSearchEngine) SearchSimilar(ctx context.Context, query string, topK int) ([]plugin.VectorSearchResult, error) {
	if e.client == nil {
		return nil, fmt.Errorf("weaviate client not initialized")
	}
	if topK <= 0 {
		topK = 10
	}

	log.Debugf("weaviate: SearchSimilar query=%q topK=%d model=%s", query, topK, e.Config.EmbeddingModel)

	// Generate embedding for the query text.
	log.Debugf("weaviate: generating query embedding via %s model=%s", e.Config.EmbeddingAPIHost, e.Config.EmbeddingModel)
	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.EmbeddingAPIHost, e.Config.EmbeddingAPIKey, e.Config.EmbeddingModel, query)
	if err != nil {
		log.Errorf("weaviate: generate query embedding failed: %v", err)
		return nil, fmt.Errorf("generate query embedding: %w", err)
	}
	log.Debugf("weaviate: query embedding generated, dimensions=%d", len(embedding))

	embeddingFloats := make([]float32, len(embedding))
	copy(embeddingFloats, embedding)

	nearVector := e.client.GraphQL().NearVectorArgBuilder().WithVector(embeddingFloats)

	fields := []graphql.Field{
		{Name: "objectID"},
		{Name: "objectType"},
		{Name: "title"},
		{Name: "metadata"},
		{Name: "_additional", Fields: []graphql.Field{
			{Name: "certainty"},
			{Name: "id"},
		}},
	}

	log.Debugf("weaviate: executing nearVector search on class=%s limit=%d", className, topK)
	result, err := e.client.GraphQL().Get().
		WithClassName(className).
		WithFields(fields...).
		WithNearVector(nearVector).
		WithLimit(topK).
		Do(ctx)
	if err != nil {
		log.Errorf("weaviate: nearVector search failed: %v", err)
		return nil, fmt.Errorf("weaviate nearVector search failed: %w", err)
	}

	if result.Errors != nil {
		msgs := make([]string, 0, len(result.Errors))
		for _, e := range result.Errors {
			msgs = append(msgs, e.Message)
		}
		log.Errorf("weaviate: GraphQL errors: %s", strings.Join(msgs, "; "))
		return nil, fmt.Errorf("weaviate GraphQL errors: %s", strings.Join(msgs, "; "))
	}

	data, ok := result.Data["Get"].(map[string]interface{})
	if !ok {
		log.Warnf("weaviate: unexpected response format from GraphQL")
		return nil, fmt.Errorf("unexpected response format")
	}
	objects, ok := data[className].([]interface{})
	if !ok {
		log.Debugf("weaviate: no objects returned from search")
		return nil, nil
	}

	log.Debugf("weaviate: search returned %d raw results", len(objects))

	results := make([]plugin.VectorSearchResult, 0, len(objects))
	filtered := 0
	for _, obj := range objects {
		m, ok := obj.(map[string]interface{})
		if !ok {
			continue
		}

		objectID, _ := m["objectID"].(string)
		objectType, _ := m["objectType"].(string)
		metadata, _ := m["metadata"].(string)

		score := 0.0
		if additional, ok := m["_additional"].(map[string]interface{}); ok {
			if certainty, ok := additional["certainty"].(float64); ok {
				// Weaviate certainty is in [0, 1] where 1 = identical.
				score = certainty
			}
		}

		if e.Config.SimilarityThreshold > 0 && score < e.Config.SimilarityThreshold {
			log.Debugf("weaviate: filtered out objectID=%s score=%.4f < threshold=%.4f", objectID, score, e.Config.SimilarityThreshold)
			filtered++
			continue
		}

		log.Debugf("weaviate: result objectID=%s objectType=%s score=%.4f", objectID, objectType, score)
		results = append(results, plugin.VectorSearchResult{
			ObjectID:   objectID,
			ObjectType: objectType,
			Metadata:   metadata,
			Score:      score,
		})
	}

	log.Debugf("weaviate: SearchSimilar done, returning %d results (%d filtered by threshold)", len(results), filtered)
	return results, nil
}

// UpdateContent upserts a single document into Weaviate.
func (e *VectorSearchEngine) UpdateContent(ctx context.Context, content *plugin.VectorSearchContent) error {
	if e.client == nil {
		return fmt.Errorf("weaviate client not initialized")
	}

	log.Debugf("weaviate: UpdateContent objectID=%s objectType=%s title=%q contentLen=%d",
		content.ObjectID, content.ObjectType, content.Title, len(content.Content))

	log.Debugf("weaviate: generating embedding for objectID=%s via %s model=%s",
		content.ObjectID, e.Config.EmbeddingAPIHost, e.Config.EmbeddingModel)
	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.EmbeddingAPIHost, e.Config.EmbeddingAPIKey, e.Config.EmbeddingModel, content.Content)
	if err != nil {
		log.Errorf("weaviate: generate embedding for %s failed: %v", content.ObjectID, err)
		return fmt.Errorf("generate embedding for %s: %w", content.ObjectID, err)
	}
	log.Debugf("weaviate: embedding generated for objectID=%s dimensions=%d", content.ObjectID, len(embedding))

	embeddingFloats := make([]float32, len(embedding))
	copy(embeddingFloats, embedding)

	properties := map[string]interface{}{
		"objectID":   content.ObjectID,
		"objectType": content.ObjectType,
		"title":      content.Title,
		"content":    content.Content,
		"metadata":   content.Metadata,
	}

	// Use deterministic UUID so repeated upserts for the same objectID overwrite.
	uuid := deterministicUUID(content.ObjectID)
	log.Debugf("weaviate: upsert objectID=%s uuid=%s", content.ObjectID, uuid)

	// Check if object already exists.
	_, err = e.client.Data().ObjectsGetter().
		WithClassName(className).
		WithID(uuid).
		Do(ctx)
	if err == nil {
		// Object exists, update it.
		log.Debugf("weaviate: updating existing object objectID=%s uuid=%s", content.ObjectID, uuid)
		err = e.client.Data().Updater().
			WithClassName(className).
			WithID(uuid).
			WithProperties(properties).
			WithVector(embeddingFloats).
			Do(ctx)
	} else {
		// Object does not exist, create it.
		log.Debugf("weaviate: creating new object objectID=%s uuid=%s", content.ObjectID, uuid)
		_, err = e.client.Data().Creator().
			WithClassName(className).
			WithProperties(properties).
			WithVector(embeddingFloats).
			WithID(uuid).
			Do(ctx)
	}

	if err != nil {
		log.Errorf("weaviate: upsert document %s failed: %v", content.ObjectID, err)
		return fmt.Errorf("upsert document %s: %w", content.ObjectID, err)
	}
	log.Debugf("weaviate: upsert objectID=%s done", content.ObjectID)
	return nil
}

// DeleteContent removes a document by object ID.
func (e *VectorSearchEngine) DeleteContent(ctx context.Context, objectID string) error {
	if e.client == nil {
		return fmt.Errorf("weaviate client not initialized")
	}

	// Delete using deterministic UUID.
	uuid := deterministicUUID(objectID)
	log.Debugf("weaviate: DeleteContent objectID=%s uuid=%s", objectID, uuid)
	err := e.client.Data().Deleter().
		WithClassName(className).
		WithID(uuid).
		Do(ctx)
	if err != nil {
		log.Errorf("weaviate: delete document %s failed: %v", objectID, err)
		return fmt.Errorf("delete document %s: %w", objectID, err)
	}
	log.Debugf("weaviate: deleted objectID=%s", objectID)
	return nil
}

// ConfigFields returns the plugin configuration form fields.
func (e *VectorSearchEngine) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "endpoint",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigEndpointTitle),
			Description: plugin.MakeTranslator(i18n.ConfigEndpointDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: e.Config.Endpoint,
		},
		{
			Name:        "api_key",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigAPIKeyTitle),
			Description: plugin.MakeTranslator(i18n.ConfigAPIKeyDescription),
			Required:    false,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypePassword,
			},
			Value: e.Config.APIKey,
		},
		{
			Name:        "embedding_api_host",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigEmbeddingAPIHostTitle),
			Description: plugin.MakeTranslator(i18n.ConfigEmbeddingAPIHostDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: e.Config.EmbeddingAPIHost,
		},
		{
			Name:        "embedding_api_key",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigEmbeddingAPIKeyTitle),
			Description: plugin.MakeTranslator(i18n.ConfigEmbeddingAPIKeyDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypePassword,
			},
			Value: e.Config.EmbeddingAPIKey,
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

	if !plugin.StatusManager.IsEnabled("weaviate_vector_search") {
		log.Debugf("weaviate: plugin not active, skipping initialization")
		return nil
	}

	log.Debugf("weaviate: initializing client: endpoint=%s scheme=%s host=%s apiKey=%v",
		conf.Endpoint, parseScheme(conf.Endpoint), stripScheme(conf.Endpoint), conf.APIKey != "")
	log.Debugf("weaviate: embedding config: host=%s model=%s level=%s threshold=%.2f",
		conf.EmbeddingAPIHost, conf.EmbeddingModel, conf.EmbeddingLevel, conf.SimilarityThreshold)

	cfg := weaviate.Config{
		Host:   stripScheme(conf.Endpoint),
		Scheme: parseScheme(conf.Endpoint),
	}
	if conf.APIKey != "" {
		cfg.AuthConfig = auth.ApiKey{Value: conf.APIKey}
	}

	client, err := weaviate.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("create weaviate client: %w", err)
	}

	// Verify connectivity.
	log.Debugf("weaviate: checking liveness at %s", conf.Endpoint)
	live, err := client.Misc().LiveChecker().Do(context.Background())
	if err != nil || !live {
		log.Errorf("weaviate: liveness check failed: live=%v err=%v", live, err)
		return fmt.Errorf("weaviate not reachable at %s: %v", conf.Endpoint, err)
	}
	log.Debugf("weaviate: liveness check passed")
	e.client = client

	// Create/ensure the class with vector configuration.
	// If it fails with auth error and API key was set, retry without auth (anonymous access).
	if err := e.ensureClass(context.Background()); err != nil {
		if conf.APIKey != "" {
			log.Debugf("weaviate: ensureClass failed with API key auth, retrying without auth (anonymous access)")
			cfg.AuthConfig = nil
			client, err = weaviate.NewClient(cfg)
			if err != nil {
				return fmt.Errorf("create weaviate client: %w", err)
			}
			e.client = client
			if err := e.ensureClass(context.Background()); err != nil {
				return fmt.Errorf("ensure class: %w", err)
			}
		} else {
			return fmt.Errorf("ensure class: %w", err)
		}
	}

	return nil
}

// ensureClass creates the Weaviate class if it doesn't exist.
func (e *VectorSearchEngine) ensureClass(ctx context.Context) error {
	log.Debugf("weaviate: checking if class %s exists", className)
	exists, err := e.client.Schema().ClassExistenceChecker().
		WithClassName(className).
		Do(ctx)
	if err != nil {
		log.Errorf("weaviate: class existence check failed: %v", err)
		return err
	}
	if exists {
		log.Debugf("weaviate: class %s already exists", className)
		return nil
	}

	log.Debugf("weaviate: creating class %s with vectorizer=none", className)

	classObj := &models.Class{
		Class:           className,
		Description:     "Answer vector search documents",
		VectorIndexType: "hnsw",
		Properties: []*models.Property{
			{
				Name:         "objectID",
				DataType:     []string{"text"},
				Description:  "Unique object identifier (question or answer ID)",
				Tokenization: "field",
			},
			{
				Name:         "objectType",
				DataType:     []string{"text"},
				Description:  "Type of object: question or answer",
				Tokenization: "field",
			},
			{
				Name:        "title",
				DataType:    []string{"text"},
				Description: "Title of the question",
			},
			{
				Name:        "content",
				DataType:    []string{"text"},
				Description: "Aggregated text content",
			},
			{
				Name:         "metadata",
				DataType:     []string{"text"},
				Description:  "JSON metadata for link composition",
				Tokenization: "field",
			},
		},
		// Use "none" vectorizer since we supply vectors externally via GenerateEmbedding.
		Vectorizer: "none",
	}

	err = e.client.Schema().ClassCreator().
		WithClass(classObj).
		Do(ctx)
	if err != nil {
		return fmt.Errorf("create class %s: %w", className, err)
	}
	log.Debugf("weaviate: class %s created successfully", className)
	return nil
}

// deterministicUUID generates a deterministic UUID v5 from the objectID string.
func deterministicUUID(objectID string) string {
	h := sha1.Sum([]byte(objectID))
	// Set version bits to 5 (0101) and variant bits to RFC 4122 (10).
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// stripScheme removes the http:// or https:// prefix from a URL.
func stripScheme(endpoint string) string {
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	return strings.TrimRight(endpoint, "/")
}

// parseScheme extracts the scheme from a URL, defaulting to "http".
func parseScheme(endpoint string) string {
	if strings.HasPrefix(endpoint, "https://") {
		return "https"
	}
	return "http"
}
