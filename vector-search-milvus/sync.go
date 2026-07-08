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

	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
)

func (e *VectorSearchEngine) sync() {
	if e.syncer == nil {
		log.Warn("milvus: syncer not registered, skip sync")
		return
	}
	e.lock.Lock()
	if e.syncing {
		e.lock.Unlock()
		log.Warn("milvus: sync already running, skip")
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
			log.Info("milvus: starting question sync...")
			page = 1
			for {
				log.Infof("milvus: sync questions page %d", page)
				questions, err := e.syncer.GetQuestionsPage(context.TODO(), page, pageSize)
				if err != nil {
					log.Errorf("milvus: get questions page failed: %v", err)
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
			log.Info("milvus: starting answer sync...")
			page = 1
			for {
				log.Infof("milvus: sync answers page %d", page)
				answers, err := e.syncer.GetAnswersPage(context.TODO(), page, pageSize)
				if err != nil {
					log.Errorf("milvus: get answers page failed: %v", err)
					break
				}
				if len(answers) == 0 {
					break
				}
				e.bulkIndex(context.TODO(), answers)
				page++
			}
		}

		log.Info("milvus: sync complete")
	}()
}

func (e *VectorSearchEngine) bulkIndex(ctx context.Context, contents []*plugin.VectorSearchContent) {
	log.Debugf("milvus: bulkIndex batch size=%d", len(contents))
	success, failed := 0, 0
	for _, c := range contents {
		if err := e.UpdateContent(ctx, c); err != nil {
			log.Warnf("milvus: index %s failed: %v", c.ObjectID, err)
			failed++
		} else {
			success++
		}
	}
	log.Debugf("milvus: bulkIndex batch done, success=%d failed=%d", success, failed)
}
