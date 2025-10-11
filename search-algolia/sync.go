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

package algolia

import (
	"context"
	"github.com/algolia/algoliasearch-client-go/v4/algolia/search"
	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
)

func (s *SearchAlgolia) sync() {
	var page, pageSize = 1, 100
	go func() {
		log.Info("algolia: start sync questions...")
		page = 1
		for {
			log.Infof("algolia: sync question page %d, page size %d", page, pageSize)
			questionList, err := s.syncer.GetQuestionsPage(context.TODO(), page, pageSize)
			if err != nil {
				log.Error("algolia: sync questions error", err)
				break
			}
			if len(questionList) == 0 {
				break
			}
			err = s.batchUpdateContent(context.TODO(), questionList)
			if err != nil {
				log.Error("algolia: sync questions error", err)
			}
			page += 1
		}

		log.Info("algolia: start sync answers...")
		page = 1
		for {
			log.Infof("algolia: sync answer page %d, page size %d", page, pageSize)
			answerList, err := s.syncer.GetAnswersPage(context.TODO(), page, pageSize)
			if err != nil {
				log.Error("algolia: sync answers error", err)
				break
			}

			if len(answerList) == 0 {
				break
			}

			err = s.batchUpdateContent(context.TODO(), answerList)
			if err != nil {
				log.Error("algolia: sync answers error", err)
			}

			page += 1
		}
		log.Info("algolia: sync done")
	}()
}

func (s *SearchAlgolia) batchUpdateContent(ctx context.Context, contents []*plugin.SearchContent) (err error) {

	// Prepare your records as a slice of map[string]any
	var records []map[string]any
	for _, content := range contents {
		record := s.parseRecordData(content)
		records = append(records, record)
	}

	// Batch insert with transformation (API v4)
	response, err := s.client.SaveObjects(
		s.getIndexName(""),
		records,
		search.WithWaitForTasks(true), // Optional: wait for indexing to complete
	)
	if err != nil {
		return
	}

	// Use response as needed
	_ = response
	return
}
