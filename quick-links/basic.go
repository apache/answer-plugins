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

// Package quick_links
package quick_links

import (
	"embed"
	"encoding/json"

	"github.com/apache/answer-plugins/quick-links/i18n"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"
)

//go:embed  info.yaml
var Info embed.FS

type QuickLinks struct {
	Config *plugin.SidebarConfig
}

func init() {
	plugin.Register(&QuickLinks{
		Config: &plugin.SidebarConfig{},
	})
}

func (q *QuickLinks) Info() plugin.Info {
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

func (e *QuickLinks) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "tags",
			Type:        plugin.ConfigTypeTagSelector,
			Title:       plugin.MakeTranslator(i18n.ConfigTagsTitle),
			Description: plugin.MakeTranslator(i18n.ConfigTagsDescription),
			Value:       e.Config.Tags,
		},
		{
			Name:        "links_text",
			Type:        plugin.ConfigTypeTextarea,
			Title:       plugin.MakeTranslator(i18n.ConfigLinksTitle),
			Description: plugin.MakeTranslator(i18n.ConfigLinksDescription),
			Value:       e.Config.LinksText,
			UIOptions: plugin.ConfigFieldUIOptions{
				Rows:      "5",
				ClassName: "small font-monospace",
			},
		},
	}
}

func (e *QuickLinks) ConfigReceiver(config []byte) error {
	c := &plugin.SidebarConfig{}
	_ = json.Unmarshal(config, c)
	e.Config = c
	return nil
}

// todo
func (q *QuickLinks) GetSidebarConfig() (sidebarConfig *plugin.SidebarConfig, err error) {
	sidebarConfig = q.Config
	return
}
