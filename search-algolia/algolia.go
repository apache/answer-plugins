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
	"embed"
	"encoding/json"
	"github.com/segmentfault/pacman/log"
	"strconv"
	"strings"
	"sync"

	"github.com/algolia/algoliasearch-client-go/v4/algolia/search"
	"github.com/apache/answer-plugins/search-algolia/i18n"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"
)

//go:embed  info.yaml
var Info embed.FS

type SearchAlgolia struct {
	Config *AlgoliaSearchConfig
	client *search.APIClient
	syncer plugin.SearchSyncer
	once   sync.Once
}

func init() {
	uc := &SearchAlgolia{Config: &AlgoliaSearchConfig{}}
	plugin.Register(uc)
}

func (s *SearchAlgolia) Info() plugin.Info {
	info := &util.Info{}
	info.GetInfo(Info)

	return plugin.Info{
		Name:        plugin.MakeTranslator(i18n.InfoName),
		SlugName:    info.SlugName,
		Description: plugin.MakeTranslator(i18n.InfoDescription),
		Version:     info.Version,
		Author:      info.Author,
		Link:        info.Link,
	}
}

func (s *SearchAlgolia) Description() plugin.SearchDesc {
	desc := plugin.SearchDesc{}
	if s.Config.ShowLogo {
		desc.Icon = icon
		desc.Link = "https://www.algolia.com/"
	}
	return desc
}

func (s *SearchAlgolia) RegisterSyncer(ctx context.Context, syncer plugin.SearchSyncer) {
	s.syncer = syncer
	s.sync()
}

func (s *SearchAlgolia) SearchContents(ctx context.Context, cond *plugin.SearchBasicCond) (res []plugin.SearchResult, total int64, err error) {
	var (
		filters      = "status<10"
		tagFilters   []string
		userIDFilter string
		votesFilter  string
	)
	if len(cond.TagIDs) > 0 {
		for _, tagGroup := range cond.TagIDs {
			var tagsIn []string
			if len(tagGroup) > 0 {
				for _, tagID := range tagGroup {
					tagsIn = append(tagsIn, "tags:"+tagID)
				}
			}
			tagFilters = append(tagFilters, "("+strings.Join(tagsIn, " OR ")+")")
		}
		if len(tagFilters) > 0 {
			filters += " AND " + strings.Join(tagFilters, " AND ")
		}
	}
	if len(cond.UserID) > 0 {
		userIDFilter = "userID:" + cond.UserID
		filters += " AND " + userIDFilter
	}
	if cond.VoteAmount == 0 {
		votesFilter = "votes=" + strconv.Itoa(cond.VoteAmount)
		filters += " AND " + votesFilter
	} else if cond.VoteAmount > 0 {
		votesFilter = "votes>=" + strconv.Itoa(cond.VoteAmount)
		filters += " AND " + votesFilter
	}

	var (
		query = strings.TrimSpace(strings.Join(cond.Words, " "))

		qres *search.SearchResponse
	)
	qres, err = s.client.SearchSingleIndex(
		s.client.NewApiSearchSingleIndexRequest(
			s.getIndexName(string(cond.Order))).
			WithSearchParams(
				search.SearchParamsObjectAsSearchParams(
					search.NewEmptySearchParamsObject().
						SetQuery(query).
						SetAttributesToRetrieve([]string{"objectID", "type"}).
						SetFilters(filters).
						SetPage(int32(cond.Page - 1)).
						SetHitsPerPage(int32(cond.PageSize)),
				),
			),
	)
	if err != nil {
		return
	}
	if qres == nil {
		return
	}
	for _, hit := range qres.Hits {
		res = append(res, plugin.SearchResult{
			ID:   hit.ObjectID,
			Type: "question",
		})
	}
	total = int64(*qres.NbHits)
	return res, total, err
}

func (s *SearchAlgolia) SearchQuestions(ctx context.Context, cond *plugin.SearchBasicCond) (res []plugin.SearchResult, total int64, err error) {
	var (
		filters       = "status<10 AND type:question"
		tagFilters    []string
		userIDFilter  string
		viewsFilter   string
		answersFilter string
	)
	if len(cond.TagIDs) > 0 {
		for _, tagGroup := range cond.TagIDs {
			var tagsIn []string
			if len(tagGroup) > 0 {
				for _, tagID := range tagGroup {
					tagsIn = append(tagsIn, "tags:"+tagID)
				}
			}
			tagFilters = append(tagFilters, "("+strings.Join(tagsIn, " OR ")+")")
		}
		if len(tagFilters) > 0 {
			filters += " AND " + strings.Join(tagFilters, " AND ")
		}
	}
	if cond.QuestionAccepted == plugin.AcceptedCondFalse {
		userIDFilter = "hasAccepted:false"
		filters += " AND " + userIDFilter
	}

	if cond.ViewAmount > -1 {
		viewsFilter = "views>=" + strconv.Itoa(cond.ViewAmount)
		filters += " AND " + viewsFilter
	}

	// check answers
	if cond.AnswerAmount == 0 {
		answersFilter = "answers=0"
		filters += " AND " + answersFilter
	} else if cond.AnswerAmount > 0 {
		answersFilter = "answers>=" + strconv.Itoa(cond.AnswerAmount)
		filters += " AND " + answersFilter
	}

	var (
		query = strings.TrimSpace(strings.Join(cond.Words, " "))
		qres  *search.SearchResponse
	)

	qres, err = s.client.SearchSingleIndex(
		s.client.NewApiSearchSingleIndexRequest(
			s.getIndexName(string(cond.Order))).
			WithSearchParams(
				search.SearchParamsObjectAsSearchParams(
					search.NewEmptySearchParamsObject().
						SetQuery(query).
						SetAttributesToRetrieve([]string{"objectID", "type"}).
						SetFilters(filters).
						SetPage(int32(cond.Page - 1)).
						SetHitsPerPage(int32(cond.PageSize)),
				),
			),
	)
	if err != nil {
		return
	}
	if qres == nil {
		return
	}
	for _, hit := range qres.Hits {
		res = append(res, plugin.SearchResult{
			ID:   hit.ObjectID,
			Type: "question",
		})
	}

	total = int64(*qres.NbHits)
	return res, total, err
}

func (s *SearchAlgolia) SearchAnswers(ctx context.Context, cond *plugin.SearchBasicCond) (res []plugin.SearchResult, total int64, err error) {
	var (
		filters          = "status<10 AND type:answer"
		tagFilters       []string
		userIDFilter     string
		questionIDFilter string
	)
	if len(cond.TagIDs) > 0 {
		for _, tagGroup := range cond.TagIDs {
			var tagsIn []string
			if len(tagGroup) > 0 {
				for _, tagID := range tagGroup {
					tagsIn = append(tagsIn, "tags:"+tagID)
				}
			}
			tagFilters = append(tagFilters, "("+strings.Join(tagsIn, " OR ")+")")
		}
		if len(tagFilters) > 0 {
			filters += " AND " + strings.Join(tagFilters, " AND ")
		}
	}
	if cond.AnswerAccepted == plugin.AcceptedCondTrue {
		userIDFilter = "hasAccepted=true"
		filters += " AND " + userIDFilter
	}

	if len(cond.QuestionID) > 0 {
		questionIDFilter = "questionID=" + cond.QuestionID
		filters += questionIDFilter
	}

	var (
		query = strings.TrimSpace(strings.Join(cond.Words, " "))
		qres  *search.SearchResponse
	)

	qres, err = s.client.SearchSingleIndex(
		s.client.NewApiSearchSingleIndexRequest(
			s.getIndexName(string(cond.Order))).
			WithSearchParams(
				search.SearchParamsObjectAsSearchParams(
					search.NewEmptySearchParamsObject().
						SetQuery(query).
						SetAttributesToRetrieve([]string{"objectID", "type"}).
						SetFilters(filters).
						SetPage(int32(cond.Page - 1)).
						SetHitsPerPage(int32(cond.PageSize)),
				),
			),
	)
	for _, hit := range qres.Hits {
		res = append(res, plugin.SearchResult{
			ID:   hit.ObjectID,
			Type: "question",
		})
	}
	total = int64(*qres.NbHits)
	return res, total, err
}

// UpdateContent updates the content to algolia server
func (s *SearchAlgolia) UpdateContent(ctx context.Context, content *plugin.SearchContent) (err error) {
	var data map[string]any
	j, err := json.Marshal(content)
	if err != nil {
		return
	}

	err = json.Unmarshal(j, &data)

	_, err = s.client.SaveObject(s.client.NewApiSaveObjectRequest(s.getIndexName(""), data))
	if err != nil {
		return
	}

	return
}

// DeleteContent deletes the content
func (s *SearchAlgolia) DeleteContent(ctx context.Context, contentID string) (err error) {
	_, err = s.client.DeleteObject(s.client.NewApiDeleteObjectRequest(s.getIndexName(""), contentID))
	return
}

// connect connect to algolia server
func (s *SearchAlgolia) connect() (err error) {
	s.once.Do(func() {
		s.client, err = search.NewClient(s.Config.APPID, s.Config.APIKey)
		if err != nil {
			log.Error("algolia: connect error", err)
		}
		log.Info("algolia: connected")
	})
	return
}

func (s *SearchAlgolia) getIndexName(order string) string {
	// main index
	var idx = s.Config.Index
	switch order {
	case NewestIndex:
		// the index of sort results by newest
		idx = idx + "_" + NewestIndex
	case ActiveIndex:
		// the index of sort results by active
		idx = idx + "_" + ActiveIndex
	case ScoreIndex:
		// the index of sort results by score
		idx = idx + "_" + ScoreIndex
	}
	return idx
}
