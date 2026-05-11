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

package milvus_vector_search

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer-plugins/vector-search-milvus/i18n"
	"github.com/apache/answer/plugin"
	"github.com/milvus-io/milvus-sdk-go/v2/client"
	"github.com/milvus-io/milvus-sdk-go/v2/entity"
	"github.com/segmentfault/pacman/log"
)

//go:embed info.yaml
var Info embed.FS

const milvusCollectionName = "answer_vector_embeddings"

// VectorSearchEngine implements plugin.VectorSearch using Milvus.
type VectorSearchEngine struct {
	Config              *VectorSearchConfig
	milvusClient        client.Client
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

func (e *VectorSearchEngine) Description() plugin.VectorSearchDesc {
	return plugin.VectorSearchDesc{
		Icon: "",
		Link: "https://milvus.io/docs",
	}
}

func (e *VectorSearchEngine) RegisterSyncer(ctx context.Context, syncer plugin.VectorSearchSyncer) {
	log.Debugf("milvus: RegisterSyncer called, configured=%v", e.milvusClient != nil)
	e.syncer = syncer
	if e.milvusClient != nil {
		e.sync()
	}
}

func (e *VectorSearchEngine) SearchSimilar(ctx context.Context, query string, topK int) ([]plugin.VectorSearchResult, error) {
	if e.milvusClient == nil {
		return nil, fmt.Errorf("milvus: not initialized")
	}
	if topK <= 0 {
		topK = 10
	}

	log.Debugf("milvus: SearchSimilar query=%q topK=%d", query, topK)

	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.APIHost, e.Config.APIKey, e.Config.EmbeddingModel, query)
	if err != nil {
		return nil, fmt.Errorf("generate query embedding: %w", err)
	}

	log.Debugf("milvus: search embedding generated, dimensions=%d", len(embedding))

	vectors := []entity.Vector{entity.FloatVector(embedding)}
	sp, _ := entity.NewIndexFlatSearchParam()

	searchResult, err := e.milvusClient.Search(
		ctx,
		milvusCollectionName,
		nil,
		"",
		[]string{"object_id", "object_type", "metadata"},
		vectors,
		"embedding",
		entity.COSINE,
		topK,
		sp,
	)
	if err != nil {
		return nil, fmt.Errorf("milvus search failed: %w", err)
	}

	results := make([]plugin.VectorSearchResult, 0)
	for _, sr := range searchResult {
		var objectIDs, objectTypes, metadatas []string

		for _, field := range sr.Fields {
			switch field.Name() {
			case "object_id":
				col, ok := field.(*entity.ColumnVarChar)
				if ok {
					for i := 0; i < col.Len(); i++ {
						v, _ := col.GetAsString(i)
						objectIDs = append(objectIDs, v)
					}
				}
			case "object_type":
				col, ok := field.(*entity.ColumnVarChar)
				if ok {
					for i := 0; i < col.Len(); i++ {
						v, _ := col.GetAsString(i)
						objectTypes = append(objectTypes, v)
					}
				}
			case "metadata":
				col, ok := field.(*entity.ColumnVarChar)
				if ok {
					for i := 0; i < col.Len(); i++ {
						v, _ := col.GetAsString(i)
						metadatas = append(metadatas, v)
					}
				}
			}
		}

		for i := 0; i < sr.ResultCount; i++ {
			score := float64(sr.Scores[i])
			if e.Config.SimilarityThreshold > 0 && score < e.Config.SimilarityThreshold {
				continue
			}

			oid := ""
			if i < len(objectIDs) {
				oid = objectIDs[i]
			}
			otype := ""
			if i < len(objectTypes) {
				otype = objectTypes[i]
			}
			meta := ""
			if i < len(metadatas) {
				meta = metadatas[i]
			}

			results = append(results, plugin.VectorSearchResult{
				ObjectID:   oid,
				ObjectType: otype,
				Metadata:   meta,
				Score:      score,
			})
		}
	}

	log.Debugf("milvus: SearchSimilar returning %d results", len(results))
	return results, nil
}

func (e *VectorSearchEngine) UpdateContent(ctx context.Context, content *plugin.VectorSearchContent) error {
	if e.milvusClient == nil {
		return fmt.Errorf("milvus: not initialized")
	}

	log.Debugf("milvus: UpdateContent objectID=%s objectType=%s", content.ObjectID, content.ObjectType)

	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.APIHost, e.Config.APIKey, e.Config.EmbeddingModel, content.Content)
	if err != nil {
		return fmt.Errorf("generate embedding for %s: %w", content.ObjectID, err)
	}

	log.Debugf("milvus: embedding generated for %s, dimensions=%d", content.ObjectID, len(embedding))

	// Delete existing document for upsert semantics.
	_ = e.milvusClient.Delete(ctx, milvusCollectionName, "", fmt.Sprintf("object_id == \"%s\"", content.ObjectID))

	// Truncate fields to fit VarChar limits.
	title := truncate(content.Title, 65000)
	body := truncate(content.Content, 65000)
	meta := truncate(content.Metadata, 65000)

	_, err = e.milvusClient.Insert(ctx, milvusCollectionName, "",
		entity.NewColumnVarChar("object_id", []string{content.ObjectID}),
		entity.NewColumnVarChar("object_type", []string{content.ObjectType}),
		entity.NewColumnVarChar("title", []string{title}),
		entity.NewColumnVarChar("content", []string{body}),
		entity.NewColumnVarChar("metadata", []string{meta}),
		entity.NewColumnFloatVector("embedding", e.embeddingDimensions, [][]float32{embedding}),
	)
	if err != nil {
		return fmt.Errorf("insert document %s: %w", content.ObjectID, err)
	}

	if err := e.milvusClient.Flush(ctx, milvusCollectionName, false); err != nil {
		log.Warnf("milvus: flush after insert failed: %v", err)
	}

	log.Debugf("milvus: upserted document %s successfully", content.ObjectID)
	return nil
}

func (e *VectorSearchEngine) DeleteContent(ctx context.Context, objectID string) error {
	if e.milvusClient == nil {
		return fmt.Errorf("milvus: not initialized")
	}

	log.Debugf("milvus: DeleteContent objectID=%s", objectID)

	err := e.milvusClient.Delete(ctx, milvusCollectionName, "", fmt.Sprintf("object_id == \"%s\"", objectID))
	if err != nil {
		return fmt.Errorf("delete document %s: %w", objectID, err)
	}

	log.Debugf("milvus: deleted document %s", objectID)
	return nil
}

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

func (e *VectorSearchEngine) ConfigReceiver(config []byte) error {
	log.Debugf("milvus: ConfigReceiver called")

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

	log.Debugf("milvus: config parsed: endpoint=%s model=%s level=%s threshold=%.2f",
		conf.Endpoint, conf.EmbeddingModel, conf.EmbeddingLevel, conf.SimilarityThreshold)

	if !plugin.StatusManager.IsEnabled("milvus_vector_search") {
		log.Debugf("milvus: plugin not active, skipping initialization")
		return nil
	}

	// Auto-detect embedding dimensions.
	log.Debugf("milvus: detecting embedding dimensions via probe call")
	probeEmbedding, err := plugin.GenerateEmbedding(context.Background(), conf.APIHost, conf.APIKey, conf.EmbeddingModel, "dimension probe")
	if err != nil {
		return fmt.Errorf("detect embedding dimensions: %w", err)
	}
	e.embeddingDimensions = len(probeEmbedding)
	log.Infof("milvus: auto-detected embedding dimensions=%d for model=%s", e.embeddingDimensions, conf.EmbeddingModel)

	// Connect to Milvus.
	log.Debugf("milvus: connecting to %s", conf.Endpoint)
	if e.milvusClient != nil {
		e.milvusClient.Close()
	}

	c, err := client.NewGrpcClient(context.Background(), conf.Endpoint)
	if err != nil {
		return fmt.Errorf("connect to milvus: %w", err)
	}
	e.milvusClient = c

	if err := e.ensureCollection(context.Background()); err != nil {
		return fmt.Errorf("ensure collection: %w", err)
	}

	log.Debugf("milvus: ConfigReceiver completed successfully")
	return nil
}

func (e *VectorSearchEngine) ensureCollection(ctx context.Context) error {
	exists, err := e.milvusClient.HasCollection(ctx, milvusCollectionName)
	if err != nil {
		return fmt.Errorf("check collection existence: %w", err)
	}

	if exists {
		// Check dimensions match.
		col, err := e.milvusClient.DescribeCollection(ctx, milvusCollectionName)
		if err != nil {
			return fmt.Errorf("describe collection: %w", err)
		}

		for _, field := range col.Schema.Fields {
			if field.Name == "embedding" {
				if dimStr, ok := field.TypeParams["dim"]; ok {
					dim, _ := strconv.Atoi(dimStr)
					if dim > 0 && dim != e.embeddingDimensions {
						log.Warnf("milvus: dimensions changed from %d to %d, recreating collection", dim, e.embeddingDimensions)
						if err := e.milvusClient.DropCollection(ctx, milvusCollectionName); err != nil {
							return fmt.Errorf("drop collection: %w", err)
						}
						exists = false
					}
				}
			}
		}
	}

	if exists {
		log.Debugf("milvus: collection %s already exists", milvusCollectionName)
		// Ensure loaded.
		if err := e.milvusClient.LoadCollection(ctx, milvusCollectionName, false); err != nil {
			log.Warnf("milvus: load collection: %v", err)
		}
		return nil
	}

	// Create collection.
	log.Debugf("milvus: creating collection %s with dims=%d", milvusCollectionName, e.embeddingDimensions)

	schema := &entity.Schema{
		CollectionName: milvusCollectionName,
		Description:    "Answer vector search documents",
		Fields: []*entity.Field{
			{
				Name:       "object_id",
				DataType:   entity.FieldTypeVarChar,
				PrimaryKey: true,
				TypeParams: map[string]string{"max_length": "256"},
			},
			{
				Name:       "object_type",
				DataType:   entity.FieldTypeVarChar,
				TypeParams: map[string]string{"max_length": "64"},
			},
			{
				Name:       "title",
				DataType:   entity.FieldTypeVarChar,
				TypeParams: map[string]string{"max_length": "65535"},
			},
			{
				Name:       "content",
				DataType:   entity.FieldTypeVarChar,
				TypeParams: map[string]string{"max_length": "65535"},
			},
			{
				Name:       "metadata",
				DataType:   entity.FieldTypeVarChar,
				TypeParams: map[string]string{"max_length": "65535"},
			},
			{
				Name:       "embedding",
				DataType:   entity.FieldTypeFloatVector,
				TypeParams: map[string]string{"dim": strconv.Itoa(e.embeddingDimensions)},
			},
		},
	}

	if err := e.milvusClient.CreateCollection(ctx, schema, 2); err != nil {
		return fmt.Errorf("create collection: %w", err)
	}

	// Create index on embedding field.
	idx, err := entity.NewIndexIvfFlat(entity.COSINE, 128)
	if err != nil {
		return fmt.Errorf("create index params: %w", err)
	}
	if err := e.milvusClient.CreateIndex(ctx, milvusCollectionName, "embedding", idx, false); err != nil {
		return fmt.Errorf("create index: %w", err)
	}

	// Load collection into memory for search.
	if err := e.milvusClient.LoadCollection(ctx, milvusCollectionName, false); err != nil {
		return fmt.Errorf("load collection: %w", err)
	}

	log.Debugf("milvus: collection %s created and loaded successfully", milvusCollectionName)
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
