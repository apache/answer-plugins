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

package chromadb_vector_search

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer-plugins/vector-search-chromadb/i18n"
	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
)

//go:embed info.yaml
var Info embed.FS

const collectionName = "answer_vector_embeddings"

// VectorSearchEngine implements plugin.VectorSearch using ChromaDB REST API.
type VectorSearchEngine struct {
	Config              *VectorSearchConfig
	httpClient          *http.Client
	collectionID        string
	syncer              plugin.VectorSearchSyncer
	syncing             bool
	lock                sync.Mutex
	embeddingDimensions int
}

// VectorSearchConfig holds all plugin configuration.
type VectorSearchConfig struct {
	Endpoint            string  `json:"endpoint"`
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
		Link: "https://docs.trychroma.com/",
	}
}

// RegisterSyncer stores the syncer and triggers a full sync.
func (e *VectorSearchEngine) RegisterSyncer(ctx context.Context, syncer plugin.VectorSearchSyncer) {
	log.Debugf("chromadb: RegisterSyncer called, configured=%v", e.httpClient != nil)
	e.syncer = syncer
	if e.httpClient != nil {
		e.sync()
	}
}

// SearchSimilar performs a cosine similarity search via ChromaDB REST API.
func (e *VectorSearchEngine) SearchSimilar(ctx context.Context, query string, topK int) ([]plugin.VectorSearchResult, error) {
	if e.httpClient == nil || e.collectionID == "" {
		return nil, fmt.Errorf("chromadb: not initialized")
	}
	if topK <= 0 {
		topK = 10
	}

	log.Debugf("chromadb: SearchSimilar query=%q topK=%d", query, topK)

	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.APIHost, e.Config.APIKey, e.Config.EmbeddingModel, query)
	if err != nil {
		return nil, fmt.Errorf("generate query embedding: %w", err)
	}

	log.Debugf("chromadb: search embedding generated, dimensions=%d", len(embedding))

	embeddingF64 := float32ToFloat64(embedding)

	reqBody := map[string]interface{}{
		"query_embeddings": [][]float64{embeddingF64},
		"n_results":        topK,
		"include":          []string{"metadatas", "distances"},
	}

	respBody, err := e.doRequest(ctx, "POST",
		fmt.Sprintf("/api/v1/collections/%s/query", e.collectionID), reqBody)
	if err != nil {
		return nil, fmt.Errorf("chromadb query failed: %w", err)
	}

	var queryResp struct {
		IDs       [][]string               `json:"ids"`
		Distances [][]float64              `json:"distances"`
		Metadatas [][]map[string]string    `json:"metadatas"`
	}
	if err := json.Unmarshal(respBody, &queryResp); err != nil {
		return nil, fmt.Errorf("parse query response: %w", err)
	}

	if len(queryResp.IDs) == 0 || len(queryResp.IDs[0]) == 0 {
		return nil, nil
	}

	results := make([]plugin.VectorSearchResult, 0, len(queryResp.IDs[0]))
	for i, id := range queryResp.IDs[0] {
		// ChromaDB cosine distance: 0 = identical, 2 = opposite. Convert to similarity score.
		score := 1.0 - queryResp.Distances[0][i]/2.0
		if e.Config.SimilarityThreshold > 0 && score < e.Config.SimilarityThreshold {
			log.Debugf("chromadb: skipping result %s score=%.4f below threshold=%.4f", id, score, e.Config.SimilarityThreshold)
			continue
		}

		meta := queryResp.Metadatas[0][i]
		results = append(results, plugin.VectorSearchResult{
			ObjectID:   id,
			ObjectType: meta["object_type"],
			Metadata:   meta["metadata"],
			Score:      score,
		})
	}

	log.Debugf("chromadb: SearchSimilar returning %d results", len(results))
	return results, nil
}

// UpdateContent upserts a single document via ChromaDB REST API.
func (e *VectorSearchEngine) UpdateContent(ctx context.Context, content *plugin.VectorSearchContent) error {
	if e.httpClient == nil || e.collectionID == "" {
		return fmt.Errorf("chromadb: not initialized")
	}

	log.Debugf("chromadb: UpdateContent objectID=%s objectType=%s", content.ObjectID, content.ObjectType)

	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.APIHost, e.Config.APIKey, e.Config.EmbeddingModel, content.Content)
	if err != nil {
		return fmt.Errorf("generate embedding for %s: %w", content.ObjectID, err)
	}

	log.Debugf("chromadb: embedding generated for %s, dimensions=%d", content.ObjectID, len(embedding))

	embeddingF64 := float32ToFloat64(embedding)

	reqBody := map[string]interface{}{
		"ids":        []string{content.ObjectID},
		"embeddings": [][]float64{embeddingF64},
		"metadatas": []map[string]string{{
			"object_type": content.ObjectType,
			"title":       content.Title,
			"metadata":    content.Metadata,
		}},
		"documents": []string{content.Content},
	}

	_, err = e.doRequest(ctx, "POST",
		fmt.Sprintf("/api/v1/collections/%s/upsert", e.collectionID), reqBody)
	if err != nil {
		return fmt.Errorf("upsert document %s: %w", content.ObjectID, err)
	}

	log.Debugf("chromadb: upserted document %s successfully", content.ObjectID)
	return nil
}

// DeleteContent removes a document by object ID.
func (e *VectorSearchEngine) DeleteContent(ctx context.Context, objectID string) error {
	if e.httpClient == nil || e.collectionID == "" {
		return fmt.Errorf("chromadb: not initialized")
	}

	log.Debugf("chromadb: DeleteContent objectID=%s", objectID)

	reqBody := map[string]interface{}{
		"ids": []string{objectID},
	}

	_, err := e.doRequest(ctx, "POST",
		fmt.Sprintf("/api/v1/collections/%s/delete", e.collectionID), reqBody)
	if err != nil {
		return fmt.Errorf("delete document %s: %w", objectID, err)
	}

	log.Debugf("chromadb: deleted document %s", objectID)
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
	log.Debugf("chromadb: ConfigReceiver called")

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

	log.Debugf("chromadb: config parsed: endpoint=%s model=%s level=%s threshold=%.2f",
		conf.Endpoint, conf.EmbeddingModel, conf.EmbeddingLevel, conf.SimilarityThreshold)

	if !plugin.StatusManager.IsEnabled("chromadb_vector_search") {
		log.Debugf("chromadb: plugin not active, skipping initialization")
		return nil
	}

	// Auto-detect embedding dimensions via probe call.
	log.Debugf("chromadb: detecting embedding dimensions via probe call")
	probeEmbedding, err := plugin.GenerateEmbedding(context.Background(), conf.APIHost, conf.APIKey, conf.EmbeddingModel, "dimension probe")
	if err != nil {
		return fmt.Errorf("detect embedding dimensions: %w", err)
	}
	e.embeddingDimensions = len(probeEmbedding)
	log.Infof("chromadb: auto-detected embedding dimensions=%d for model=%s", e.embeddingDimensions, conf.EmbeddingModel)

	e.httpClient = &http.Client{}

	// Ensure endpoint doesn't have trailing slash.
	e.Config.Endpoint = strings.TrimRight(e.Config.Endpoint, "/")

	if err := e.ensureCollection(context.Background()); err != nil {
		return fmt.Errorf("ensure collection: %w", err)
	}

	log.Debugf("chromadb: ConfigReceiver completed successfully, collectionID=%s", e.collectionID)
	return nil
}

// ensureCollection creates or gets the ChromaDB collection.
func (e *VectorSearchEngine) ensureCollection(ctx context.Context) error {
	// Try to get existing collection.
	respBody, err := e.doRequest(ctx, "GET",
		fmt.Sprintf("/api/v1/collections/%s", collectionName), nil)
	if err == nil {
		var col struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(respBody, &col) == nil && col.ID != "" {
			e.collectionID = col.ID
			log.Debugf("chromadb: found existing collection %s id=%s", collectionName, col.ID)
			return nil
		}
	}

	// Create new collection.
	log.Debugf("chromadb: creating collection %s", collectionName)
	reqBody := map[string]interface{}{
		"name": collectionName,
		"metadata": map[string]string{
			"hnsw:space": "cosine",
		},
	}

	respBody, err = e.doRequest(ctx, "POST", "/api/v1/collections", reqBody)
	if err != nil {
		return fmt.Errorf("create collection: %w", err)
	}

	var col struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &col); err != nil {
		return fmt.Errorf("parse create collection response: %w", err)
	}
	e.collectionID = col.ID
	log.Debugf("chromadb: created collection %s id=%s", collectionName, col.ID)
	return nil
}

// doRequest sends an HTTP request to the ChromaDB server.
func (e *VectorSearchEngine) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	url := e.Config.Endpoint + path
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("chromadb returned %d: %s", resp.StatusCode, string(respData))
	}

	return respData, nil
}

// float32ToFloat64 converts a []float32 slice to []float64 for JSON serialization.
func float32ToFloat64(f32 []float32) []float64 {
	f64 := make([]float64, len(f32))
	for i, v := range f32 {
		f64[i] = float64(v)
	}
	return f64
}
