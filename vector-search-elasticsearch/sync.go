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

	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
)

// sync triggers a full bulk sync of all Q&A content into the vector store.
// It runs in a background goroutine and is guarded by the syncing flag.
func (e *VectorSearchEngine) sync() {
	if e.syncer == nil {
		log.Warn("es-vector: syncer not registered, skip sync")
		return
	}
	e.lock.Lock()
	if e.syncing {
		e.lock.Unlock()
		log.Warn("es-vector: sync already running, skip")
		return
	}
	e.syncing = true
	e.lock.Unlock()

	go func() {
		defer func() {
			e.lock.Lock()
			e.syncing = false
			e.lock.Unlock()
		}()

		page, pageSize := 1, 100

		if e.Config.EmbeddingLevel == "" || e.Config.EmbeddingLevel == "question" {
			log.Info("es-vector: starting question sync...")
			page = 1
			for {
				log.Infof("es-vector: sync questions page %d", page)
				questions, err := e.syncer.GetQuestionsPage(context.TODO(), page, pageSize)
				if err != nil {
					log.Errorf("es-vector: get questions page failed: %v", err)
					break
				}
				if len(questions) == 0 {
					break
				}
				e.bulkIndex(context.TODO(), questions)
				page++
			}
		}

		if e.Config.EmbeddingLevel == "answer" {
			log.Info("es-vector: starting answer sync...")
			page = 1
			for {
				log.Infof("es-vector: sync answers page %d", page)
				answers, err := e.syncer.GetAnswersPage(context.TODO(), page, pageSize)
				if err != nil {
					log.Errorf("es-vector: get answers page failed: %v", err)
					break
				}
				if len(answers) == 0 {
					break
				}
				e.bulkIndex(context.TODO(), answers)
				page++
			}
		}

		log.Info("es-vector: sync complete")
	}()
}

// bulkIndex indexes a batch of documents, computing embeddings for each.
func (e *VectorSearchEngine) bulkIndex(ctx context.Context, contents []*plugin.VectorSearchContent) {
	for _, c := range contents {
		if err := e.UpdateContent(ctx, c); err != nil {
			log.Warnf("es-vector: index %s failed: %v", c.ObjectID, err)
		}
	}
}
