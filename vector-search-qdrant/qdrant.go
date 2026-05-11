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

package qdrant_vector_search

import (
	"context"
	"crypto/sha1"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer-plugins/vector-search-qdrant/i18n"
	"github.com/apache/answer/plugin"
	pb "github.com/qdrant/go-client/qdrant"
	"github.com/segmentfault/pacman/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

//go:embed info.yaml
var Info embed.FS

const qdrantCollectionName = "answer_vector_embeddings"

// VectorSearchEngine implements plugin.VectorSearch using Qdrant.
type VectorSearchEngine struct {
	Config              *VectorSearchConfig
	conn                *grpc.ClientConn
	pointsClient        pb.PointsClient
	collectionsClient   pb.CollectionsClient
	syncer              plugin.VectorSearchSyncer
	syncing             bool
	lock                sync.Mutex
	embeddingDimensions int
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

func (e *VectorSearchEngine) Description() plugin.VectorSearchDesc {
	return plugin.VectorSearchDesc{
		Icon: "",
		Link: "https://qdrant.tech/documentation/",
	}
}

func (e *VectorSearchEngine) RegisterSyncer(ctx context.Context, syncer plugin.VectorSearchSyncer) {
	log.Debugf("qdrant: RegisterSyncer called, configured=%v", e.conn != nil)
	e.syncer = syncer
	if e.conn != nil {
		e.sync()
	}
}

func (e *VectorSearchEngine) SearchSimilar(ctx context.Context, query string, topK int) ([]plugin.VectorSearchResult, error) {
	if e.pointsClient == nil {
		return nil, fmt.Errorf("qdrant: not initialized")
	}
	if topK <= 0 {
		topK = 10
	}

	log.Debugf("qdrant: SearchSimilar query=%q topK=%d", query, topK)

	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.EmbeddingAPIHost, e.Config.EmbeddingAPIKey, e.Config.EmbeddingModel, query)
	if err != nil {
		return nil, fmt.Errorf("generate query embedding: %w", err)
	}

	log.Debugf("qdrant: search embedding generated, dimensions=%d", len(embedding))

	ctx = e.withAPIKey(ctx)
	limit := uint64(topK)
	searchResp, err := e.pointsClient.Search(ctx, &pb.SearchPoints{
		CollectionName: qdrantCollectionName,
		Vector:         embedding,
		Limit:          limit,
		WithPayload: &pb.WithPayloadSelector{
			SelectorOptions: &pb.WithPayloadSelector_Enable{Enable: true},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("qdrant search failed: %w", err)
	}

	results := make([]plugin.VectorSearchResult, 0, len(searchResp.Result))
	for _, point := range searchResp.Result {
		score := float64(point.Score)
		if e.Config.SimilarityThreshold > 0 && score < e.Config.SimilarityThreshold {
			log.Debugf("qdrant: skipping result score=%.4f below threshold=%.4f", score, e.Config.SimilarityThreshold)
			continue
		}

		objectID := getPayloadString(point.Payload, "object_id")
		objectType := getPayloadString(point.Payload, "object_type")
		metadataStr := getPayloadString(point.Payload, "metadata")

		results = append(results, plugin.VectorSearchResult{
			ObjectID:   objectID,
			ObjectType: objectType,
			Metadata:   metadataStr,
			Score:      score,
		})
	}

	log.Debugf("qdrant: SearchSimilar returning %d results", len(results))
	return results, nil
}

func (e *VectorSearchEngine) UpdateContent(ctx context.Context, content *plugin.VectorSearchContent) error {
	if e.pointsClient == nil {
		return fmt.Errorf("qdrant: not initialized")
	}

	log.Debugf("qdrant: UpdateContent objectID=%s objectType=%s", content.ObjectID, content.ObjectType)

	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.EmbeddingAPIHost, e.Config.EmbeddingAPIKey, e.Config.EmbeddingModel, content.Content)
	if err != nil {
		return fmt.Errorf("generate embedding for %s: %w", content.ObjectID, err)
	}

	log.Debugf("qdrant: embedding generated for %s, dimensions=%d", content.ObjectID, len(embedding))

	pointID := deterministicUUID(content.ObjectID)
	ctx = e.withAPIKey(ctx)

	_, err = e.pointsClient.Upsert(ctx, &pb.UpsertPoints{
		CollectionName: qdrantCollectionName,
		Points: []*pb.PointStruct{
			{
				Id: &pb.PointId{
					PointIdOptions: &pb.PointId_Uuid{Uuid: pointID},
				},
				Vectors: &pb.Vectors{
					VectorsOptions: &pb.Vectors_Vector{
						Vector: &pb.Vector{Data: embedding},
					},
				},
				Payload: map[string]*pb.Value{
					"object_id":   {Kind: &pb.Value_StringValue{StringValue: content.ObjectID}},
					"object_type": {Kind: &pb.Value_StringValue{StringValue: content.ObjectType}},
					"title":       {Kind: &pb.Value_StringValue{StringValue: content.Title}},
					"metadata":    {Kind: &pb.Value_StringValue{StringValue: content.Metadata}},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("upsert document %s: %w", content.ObjectID, err)
	}

	log.Debugf("qdrant: upserted document %s successfully", content.ObjectID)
	return nil
}

func (e *VectorSearchEngine) DeleteContent(ctx context.Context, objectID string) error {
	if e.pointsClient == nil {
		return fmt.Errorf("qdrant: not initialized")
	}

	log.Debugf("qdrant: DeleteContent objectID=%s", objectID)

	pointID := deterministicUUID(objectID)
	ctx = e.withAPIKey(ctx)

	_, err := e.pointsClient.Delete(ctx, &pb.DeletePoints{
		CollectionName: qdrantCollectionName,
		Points: &pb.PointsSelector{
			PointsSelectorOneOf: &pb.PointsSelector_Points{
				Points: &pb.PointsIdsList{
					Ids: []*pb.PointId{
						{PointIdOptions: &pb.PointId_Uuid{Uuid: pointID}},
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("delete document %s: %w", objectID, err)
	}

	log.Debugf("qdrant: deleted document %s", objectID)
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

func (e *VectorSearchEngine) ConfigReceiver(config []byte) error {
	log.Debugf("qdrant: ConfigReceiver called")

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

	log.Debugf("qdrant: config parsed: endpoint=%s model=%s level=%s threshold=%.2f",
		conf.Endpoint, conf.EmbeddingModel, conf.EmbeddingLevel, conf.SimilarityThreshold)

	if !plugin.StatusManager.IsEnabled("qdrant_vector_search") {
		log.Debugf("qdrant: plugin not active, skipping initialization")
		return nil
	}

	// Auto-detect embedding dimensions.
	log.Debugf("qdrant: detecting embedding dimensions via probe call")
	probeEmbedding, err := plugin.GenerateEmbedding(context.Background(), conf.EmbeddingAPIHost, conf.EmbeddingAPIKey, conf.EmbeddingModel, "dimension probe")
	if err != nil {
		return fmt.Errorf("detect embedding dimensions: %w", err)
	}
	e.embeddingDimensions = len(probeEmbedding)
	log.Infof("qdrant: auto-detected embedding dimensions=%d for model=%s", e.embeddingDimensions, conf.EmbeddingModel)

	// Connect to Qdrant via gRPC.
	log.Debugf("qdrant: connecting to %s", conf.Endpoint)
	if e.conn != nil {
		e.conn.Close()
	}

	conn, err := grpc.NewClient(conf.Endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connect to qdrant: %w", err)
	}
	e.conn = conn
	e.pointsClient = pb.NewPointsClient(conn)
	e.collectionsClient = pb.NewCollectionsClient(conn)

	if err := e.ensureCollection(context.Background()); err != nil {
		return fmt.Errorf("ensure collection: %w", err)
	}

	log.Debugf("qdrant: ConfigReceiver completed successfully")
	return nil
}

func (e *VectorSearchEngine) ensureCollection(ctx context.Context) error {
	ctx = e.withAPIKey(ctx)

	// Check if collection exists.
	listResp, err := e.collectionsClient.List(ctx, &pb.ListCollectionsRequest{})
	if err != nil {
		return fmt.Errorf("list collections: %w", err)
	}

	for _, col := range listResp.Collections {
		if col.Name == qdrantCollectionName {
			// Check dimensions match.
			infoResp, err := e.collectionsClient.Get(ctx, &pb.GetCollectionInfoRequest{
				CollectionName: qdrantCollectionName,
			})
			if err != nil {
				return fmt.Errorf("get collection info: %w", err)
			}

			existingDims := uint64(0)
			if params := infoResp.Result.Config.Params.VectorsConfig.GetParams(); params != nil {
				existingDims = params.Size
			}

			if existingDims > 0 && existingDims != uint64(e.embeddingDimensions) {
				log.Warnf("qdrant: dimensions changed from %d to %d, recreating collection", existingDims, e.embeddingDimensions)
				_, err = e.collectionsClient.Delete(ctx, &pb.DeleteCollection{
					CollectionName: qdrantCollectionName,
				})
				if err != nil {
					return fmt.Errorf("delete collection: %w", err)
				}
				break
			}

			log.Debugf("qdrant: collection %s already exists with dims=%d", qdrantCollectionName, existingDims)
			return nil
		}
	}

	// Create collection.
	log.Debugf("qdrant: creating collection %s with dims=%d", qdrantCollectionName, e.embeddingDimensions)
	_, err = e.collectionsClient.Create(ctx, &pb.CreateCollection{
		CollectionName: qdrantCollectionName,
		VectorsConfig: &pb.VectorsConfig{
			Config: &pb.VectorsConfig_Params{
				Params: &pb.VectorParams{
					Size:     uint64(e.embeddingDimensions),
					Distance: pb.Distance_Cosine,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create collection: %w", err)
	}

	log.Debugf("qdrant: collection %s created successfully", qdrantCollectionName)
	return nil
}

func (e *VectorSearchEngine) withAPIKey(ctx context.Context) context.Context {
	if e.Config.APIKey != "" {
		return metadata.AppendToOutgoingContext(ctx, "api-key", e.Config.APIKey)
	}
	return ctx
}

func getPayloadString(payload map[string]*pb.Value, key string) string {
	if v, ok := payload[key]; ok {
		return v.GetStringValue()
	}
	return ""
}

func deterministicUUID(objectID string) string {
	h := sha1.Sum([]byte(objectID))
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}
