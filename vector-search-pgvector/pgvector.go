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

package pgvector_search

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer-plugins/vector-search-pgvector/i18n"
	"github.com/apache/answer/plugin"
	_ "github.com/lib/pq"
	pgv "github.com/pgvector/pgvector-go"
	"github.com/segmentfault/pacman/log"
)

//go:embed info.yaml
var Info embed.FS

const tableName = "answer_vector_embeddings"

// VectorSearchEngine implements plugin.VectorSearch using PostgreSQL + pgvector.
type VectorSearchEngine struct {
	Config              *VectorSearchConfig
	db                  *sql.DB
	syncer              plugin.VectorSearchSyncer
	syncing             bool
	lock                sync.Mutex
	embeddingDimensions int // auto-detected from embedding model
}

// VectorSearchConfig holds all plugin configuration.
type VectorSearchConfig struct {
	DSN                 string  `json:"dsn"`
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
		Link: "https://github.com/pgvector/pgvector",
	}
}

// RegisterSyncer stores the syncer and triggers a full sync.
func (e *VectorSearchEngine) RegisterSyncer(ctx context.Context, syncer plugin.VectorSearchSyncer) {
	log.Debugf("pgvector: RegisterSyncer called, db=%v, embeddingLevel=%s", e.db != nil, e.Config.EmbeddingLevel)
	e.syncer = syncer
	if e.db != nil {
		e.sync()
	}
}

// SearchSimilar performs a cosine similarity search using pgvector.
func (e *VectorSearchEngine) SearchSimilar(ctx context.Context, query string, topK int) ([]plugin.VectorSearchResult, error) {
	if e.db == nil {
		return nil, fmt.Errorf("pgvector: database not initialized")
	}
	if topK <= 0 {
		topK = 10
	}

	log.Debugf("pgvector: SearchSimilar query=%q topK=%d model=%s", query, topK, e.Config.EmbeddingModel)

	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.APIHost, e.Config.APIKey, e.Config.EmbeddingModel, query)
	if err != nil {
		return nil, fmt.Errorf("generate query embedding: %w", err)
	}

	log.Debugf("pgvector: search embedding generated, dimensions=%d", len(embedding))

	vec := pgv.NewVector(embedding)

	// Use cosine distance operator (<=>). Score = 1 - distance.
	sqlQuery := fmt.Sprintf(
		`SELECT object_id, object_type, metadata, 1 - (embedding <=> $1) AS score
		FROM %s
		ORDER BY embedding <=> $1
		LIMIT $2`, tableName)

	rows, err := e.db.QueryContext(ctx, sqlQuery, vec, topK)
	if err != nil {
		return nil, fmt.Errorf("pgvector search failed: %w", err)
	}
	defer rows.Close()

	results := make([]plugin.VectorSearchResult, 0, topK)
	for rows.Next() {
		var r plugin.VectorSearchResult
		if err := rows.Scan(&r.ObjectID, &r.ObjectType, &r.Metadata, &r.Score); err != nil {
			log.Warnf("pgvector: scan row: %v", err)
			continue
		}
		if e.Config.SimilarityThreshold > 0 && r.Score < e.Config.SimilarityThreshold {
			log.Debugf("pgvector: skipping result %s score=%.4f below threshold=%.4f", r.ObjectID, r.Score, e.Config.SimilarityThreshold)
			continue
		}
		results = append(results, r)
	}
	log.Debugf("pgvector: SearchSimilar returning %d results", len(results))
	return results, rows.Err()
}

// UpdateContent upserts a single document into the pgvector table.
func (e *VectorSearchEngine) UpdateContent(ctx context.Context, content *plugin.VectorSearchContent) error {
	if e.db == nil {
		return fmt.Errorf("pgvector: database not initialized")
	}

	log.Debugf("pgvector: UpdateContent objectID=%s objectType=%s titleLen=%d contentLen=%d",
		content.ObjectID, content.ObjectType, len(content.Title), len(content.Content))

	embedding, err := plugin.GenerateEmbedding(ctx, e.Config.APIHost, e.Config.APIKey, e.Config.EmbeddingModel, content.Content)
	if err != nil {
		return fmt.Errorf("generate embedding for %s: %w", content.ObjectID, err)
	}

	log.Debugf("pgvector: embedding generated for %s, dimensions=%d", content.ObjectID, len(embedding))

	vec := pgv.NewVector(embedding)

	query := fmt.Sprintf(
		`INSERT INTO %s (object_id, object_type, title, content, metadata, embedding)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (object_id) DO UPDATE SET
			object_type = EXCLUDED.object_type,
			title = EXCLUDED.title,
			content = EXCLUDED.content,
			metadata = EXCLUDED.metadata,
			embedding = EXCLUDED.embedding`, tableName)

	_, err = e.db.ExecContext(ctx, query,
		content.ObjectID, content.ObjectType, content.Title, content.Content, content.Metadata, vec)
	if err != nil {
		return fmt.Errorf("upsert document %s: %w", content.ObjectID, err)
	}
	log.Debugf("pgvector: upserted document %s successfully", content.ObjectID)
	return nil
}

// DeleteContent removes a document by object ID.
func (e *VectorSearchEngine) DeleteContent(ctx context.Context, objectID string) error {
	if e.db == nil {
		return fmt.Errorf("pgvector: database not initialized")
	}
	log.Debugf("pgvector: DeleteContent objectID=%s", objectID)
	_, err := e.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE object_id = $1`, tableName), objectID)
	if err != nil {
		return fmt.Errorf("delete document %s: %w", objectID, err)
	}
	log.Debugf("pgvector: deleted document %s", objectID)
	return nil
}

// ConfigFields returns the plugin configuration form fields.
func (e *VectorSearchEngine) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "dsn",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigDSNTitle),
			Description: plugin.MakeTranslator(i18n.ConfigDSNDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: e.Config.DSN,
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
	log.Debugf("pgvector: ConfigReceiver called, config size=%d bytes", len(config))

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

	log.Debugf("pgvector: config parsed: dsn_set=%t model=%s level=%s threshold=%.2f",
		conf.DSN != "", conf.EmbeddingModel, conf.EmbeddingLevel, conf.SimilarityThreshold)

	if !plugin.StatusManager.IsEnabled("pgvector_search") {
		log.Debugf("pgvector: plugin not active, skipping initialization")
		return nil
	}

	// Auto-detect embedding dimensions by generating a probe embedding.
	log.Debugf("pgvector: detecting embedding dimensions via probe call")
	probeEmbedding, err := plugin.GenerateEmbedding(context.Background(), conf.APIHost, conf.APIKey, conf.EmbeddingModel, "dimension probe")
	if err != nil {
		return fmt.Errorf("detect embedding dimensions: %w", err)
	}
	e.embeddingDimensions = len(probeEmbedding)
	log.Infof("pgvector: auto-detected embedding dimensions=%d for model=%s", e.embeddingDimensions, conf.EmbeddingModel)

	log.Debugf("pgvector: connecting to PostgreSQL")

	db, err := sql.Open("postgres", conf.DSN)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("ping postgres: %w", err)
	}

	log.Debugf("pgvector: connected to PostgreSQL successfully")

	// Close previous connection if any.
	if e.db != nil {
		e.db.Close()
	}
	e.db = db

	if err := e.ensureTable(context.Background()); err != nil {
		return fmt.Errorf("ensure table: %w", err)
	}

	log.Debugf("pgvector: ConfigReceiver completed successfully")
	return nil
}

// ensureTable creates the pgvector extension and the embeddings table if they don't exist.
// If the table exists but the embedding dimensions differ, it drops and recreates the table.
func (e *VectorSearchEngine) ensureTable(ctx context.Context) error {
	// Enable the pgvector extension.
	if _, err := e.db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS vector`); err != nil {
		return fmt.Errorf("create vector extension: %w", err)
	}

	dims := e.embeddingDimensions
	if dims <= 0 {
		dims = 1536
	}

	log.Debugf("pgvector: ensureTable with dimensions=%d", dims)

	// Check if table exists and verify embedding dimensions match.
	var existingDims int
	err := e.db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT atttypmod FROM pg_attribute
		 WHERE attrelid = '%s'::regclass AND attname = 'embedding'`, tableName)).Scan(&existingDims)
	if err == nil && existingDims > 0 && existingDims != dims {
		log.Warnf("pgvector: embedding dimensions changed from %d to %d, recreating table", existingDims, dims)
		if _, err := e.db.ExecContext(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, tableName)); err != nil {
			return fmt.Errorf("drop table for dimension change: %w", err)
		}
	} else if err != nil {
		log.Debugf("pgvector: table does not exist yet or dimension check skipped: %v", err)
	} else {
		log.Debugf("pgvector: existing table dimensions=%d, matches configured=%d", existingDims, dims)
	}

	createSQL := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		object_id   TEXT PRIMARY KEY,
		object_type TEXT NOT NULL,
		title       TEXT NOT NULL DEFAULT '',
		content     TEXT NOT NULL DEFAULT '',
		metadata    TEXT NOT NULL DEFAULT '',
		embedding   vector(%d) NOT NULL
	)`, tableName, dims)

	if _, err := e.db.ExecContext(ctx, createSQL); err != nil {
		return fmt.Errorf("create table: %w", err)
	}

	// Create an IVFFlat index for faster cosine similarity search if it doesn't exist.
	indexSQL := fmt.Sprintf(
		`CREATE INDEX IF NOT EXISTS idx_%s_embedding ON %s USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)`,
		tableName, tableName)
	if _, err := e.db.ExecContext(ctx, indexSQL); err != nil {
		// IVFFlat requires data in the table to build the index; log and continue if empty.
		log.Warnf("pgvector: create ivfflat index (may need data first): %v", err)
	}

	return nil
}
