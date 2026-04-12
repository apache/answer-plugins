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

	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
)

func (e *VectorSearchEngine) sync() {
	if e.syncer == nil {
		log.Warn("memory: syncer not registered, skip sync")
		return
	}
	if e.syncing {
		log.Warn("memory: sync already running, skip")
		return
	}

	go func() {
		e.lock.Lock()
		defer e.lock.Unlock()
		if e.syncing {
			return
		}
		e.syncing = true
		defer func() { e.syncing = false }()

		page, pageSize := 1, 100

		if e.Config.EmbeddingLevel == "" || e.Config.EmbeddingLevel == "question" {
			log.Info("memory: starting question sync...")
			page = 1
			for {
				log.Infof("memory: sync questions page %d", page)
				questions, err := e.syncer.GetQuestionsPage(context.TODO(), page, pageSize)
				if err != nil {
					log.Errorf("memory: get questions page failed: %v", err)
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
			log.Info("memory: starting answer sync...")
			page = 1
			for {
				log.Infof("memory: sync answers page %d", page)
				answers, err := e.syncer.GetAnswersPage(context.TODO(), page, pageSize)
				if err != nil {
					log.Errorf("memory: get answers page failed: %v", err)
					break
				}
				if len(answers) == 0 {
					break
				}
				e.bulkIndex(context.TODO(), answers)
				page++
			}
		}

		log.Info("memory: sync complete")
	}()
}

func (e *VectorSearchEngine) bulkIndex(ctx context.Context, contents []*plugin.VectorSearchContent) {
	log.Debugf("memory: bulkIndex batch size=%d", len(contents))
	success, failed := 0, 0
	for _, c := range contents {
		if err := e.UpdateContent(ctx, c); err != nil {
			log.Warnf("memory: index %s failed: %v", c.ObjectID, err)
			failed++
		} else {
			success++
		}
	}
	log.Debugf("memory: bulkIndex batch done, success=%d failed=%d", success, failed)
}
