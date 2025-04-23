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

package basic

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/apache/answer-plugins/reviewer-basic/i18n"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"
	myI18n "github.com/segmentfault/pacman/i18n"
)

//go:embed  info.yaml
var Info embed.FS

type Reviewer struct {
	Config *ReviewerConfig
}

const (
	OptionNone  = "none"
	OptionAll   = "all"
	OptionFirst = "first"
)

type ReviewerConfig struct {
	PostAllNeedReview      bool   `json:"review_post_all"`
	PostNeedReview         bool   `json:"review_post"`
	PostReviewOption       string `json:"review_post_option"`
	PostReviewKeywords     string `json:"review_post_keywords"`
	PostDisallowedKeywords string `json:"disallowed_keywords"`
}

func init() {
	plugin.Register(&Reviewer{
		Config: &ReviewerConfig{},
	})
}

func (r *Reviewer) Info() plugin.Info {
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

func (r *Reviewer) Review(content *plugin.ReviewContent) (result *plugin.ReviewResult) {
	result = &plugin.ReviewResult{Approved: true, ReviewStatus: plugin.ReviewStatusApproved}

	// If the author is admin, no need to review
	if content.Author.Role > 1 {
		return result
	}

	if r.Config.PostReviewOption == OptionAll || (r.Config.PostReviewOption == "" && r.Config.PostAllNeedReview) {
		result = &plugin.ReviewResult{
			Approved:     false,
			ReviewStatus: plugin.ReviewStatusNeedReview,
			Reason:       plugin.TranslateWithData(myI18n.Language(content.Language), i18n.CommentNeedReview, nil),
		}
		return result
	}

	if (r.Config.PostReviewOption == OptionFirst || (r.Config.PostReviewOption == "" && r.Config.PostNeedReview)) && content.Author.ApprovedQuestionAmount+content.Author.ApprovedAnswerAmount == 0 {
		result = &plugin.ReviewResult{
			Approved:     false,
			ReviewStatus: plugin.ReviewStatusNeedReview,
			Reason:       plugin.TranslateWithData(myI18n.Language(content.Language), i18n.CommentNeedReview, nil),
		}
		return result
	}

	keywords := strings.Split(r.Config.PostReviewKeywords, "\n")
	disallowedKeywords := strings.Split(r.Config.PostDisallowedKeywords, "\n")

	// Check if the post contains the keywords that need review
	for _, keyword := range keywords {
		keyword = strings.TrimSpace(keyword)
		if len(keyword) == 0 {
			continue
		}
		keyword = strings.ToLower(keyword)
		if strings.Contains(strings.ToLower(content.Title), keyword) ||
			strings.Contains(strings.ToLower(content.Content), keyword) ||
			strings.Contains(content.IP, keyword) ||
			strings.Contains(content.UserAgent, keyword) ||
			r.checkTags(content.Tags, keyword) {
			return &plugin.ReviewResult{
				Approved:     false,
				ReviewStatus: plugin.ReviewStatusNeedReview,
				Reason:       fmt.Sprintf(plugin.TranslateWithData(myI18n.Language(content.Language), i18n.CommentMatchWordReview, nil), keyword),
			}
		}
	}

	// If the post contains the disallowed keywords
	for _, disallowedKeyword := range disallowedKeywords {
		disallowedKeyword = strings.TrimSpace(disallowedKeyword)
		if len(disallowedKeyword) == 0 {
			continue
		}
		disallowedKeyword = strings.ToLower(disallowedKeyword)
		if strings.Contains(strings.ToLower(content.Title), disallowedKeyword) ||
			strings.Contains(strings.ToLower(content.Content), disallowedKeyword) ||
			strings.Contains(content.IP, disallowedKeyword) ||
			strings.Contains(content.UserAgent, disallowedKeyword) ||
			r.checkTags(content.Tags, disallowedKeyword) {
			return &plugin.ReviewResult{
				Approved:     false,
				ReviewStatus: plugin.ReviewStatusDeleteDirectly,
				Reason:       fmt.Sprintf(plugin.TranslateWithData(myI18n.Language(content.Language), i18n.CommentMatchWordReview, nil), disallowedKeyword),
			}
		}
	}

	return result
}

func (r *Reviewer) ConfigFields() []plugin.ConfigField {
	defaultOption := OptionNone
	if r.Config.PostReviewOption == "" {
		if r.Config.PostAllNeedReview {
			defaultOption = OptionAll
		} else if r.Config.PostNeedReview {
			defaultOption = OptionFirst
		}
	} else {
		defaultOption = r.Config.PostReviewOption
	}

	return []plugin.ConfigField{
		{
			Name:      "review_post_option",
			Type:      plugin.ConfigTypeSelect,
			Title:     plugin.MakeTranslator(i18n.ConfigReviewPostTitle),
			Required:  false,
			UIOptions: plugin.ConfigFieldUIOptions{},
			Value:     defaultOption,
			Options: []plugin.ConfigFieldOption{
				{
					Value: OptionNone,
					Label: plugin.MakeTranslator(i18n.ConfigSelectOption),
				},
				{
					Value: OptionAll,
					Label: plugin.MakeTranslator(i18n.ConfigReviewPostLabelAll),
				},
				{
					Value: OptionFirst,
					Label: plugin.MakeTranslator(i18n.ConfigReviewPostLabelFirst),
				},
			},
		},
		{
			Name:  "review_post_all",
			Type:  plugin.ConfigTypeSwitch,
			Title: plugin.MakeTranslator(i18n.ConfigReviewPostTitle),
			UIOptions: plugin.ConfigFieldUIOptions{
				Label:          plugin.MakeTranslator(i18n.ConfigReviewPostLabelAll),
				FieldClassName: "mb-0",
			},
			Value: r.Config.PostAllNeedReview,
		},
		{
			Name:        "review_post",
			Type:        plugin.ConfigTypeSwitch,
			Description: plugin.MakeTranslator(i18n.ConfigReviewPostDescription),
			UIOptions: plugin.ConfigFieldUIOptions{
				Label: plugin.MakeTranslator(i18n.ConfigReviewPostLabelFirst),
			},
			Value: r.Config.PostNeedReview,
		},
		{
			Name:        "review_post_keywords",
			Type:        plugin.ConfigTypeTextarea,
			Title:       plugin.MakeTranslator(i18n.ConfigReviewPostKeywordsTitle),
			Description: plugin.MakeTranslator(i18n.ConfigReviewPostKeywordsDescription),
			Value:       r.Config.PostReviewKeywords,
		},
		{
			Name:        "disallowed_keywords",
			Type:        plugin.ConfigTypeTextarea,
			Title:       plugin.MakeTranslator(i18n.ConfigDisallowedKeywordsTitle),
			Description: plugin.MakeTranslator(i18n.ConfigDisallowedKeywordsDescription),
			Value:       r.Config.PostDisallowedKeywords,
		},
	}
}

func (r *Reviewer) ConfigReceiver(config []byte) error {
	c := &ReviewerConfig{}
	_ = json.Unmarshal(config, c)

	if c.PostReviewOption == OptionAll {
		c.PostAllNeedReview = true
		c.PostNeedReview = false
	} else if c.PostReviewOption == OptionFirst {
		c.PostAllNeedReview = false
		c.PostNeedReview = true
	} else if c.PostReviewOption == OptionNone {
		c.PostAllNeedReview = false
		c.PostNeedReview = false
	}

	r.Config = c
	return nil
}

func (r *Reviewer) checkTags(tags []string, keyword string) bool {
	for _, tag := range tags {
		if strings.Contains(strings.ToLower(tag), keyword) {
			return true
		}
	}
	return false
}
