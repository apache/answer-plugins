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

package aliyunoss

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/apache/answer/pkg/checker"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/apache/answer-plugins/storage-aliyunoss/i18n"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"
)

//go:embed  info.yaml
var Info embed.FS

type Storage struct {
	Config *StorageConfig
}

type StorageConfig struct {
	Endpoint        string `json:"endpoint"`
	BucketName      string `json:"bucket_name"`
	ObjectKeyPrefix string `json:"object_key_prefix"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	VisitUrlPrefix  string `json:"visit_url_prefix"`
}

func init() {
	plugin.Register(&Storage{
		Config: &StorageConfig{},
	})
}

func (s *Storage) Info() plugin.Info {
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

func (s *Storage) UploadFile(ctx *plugin.GinContext, condition plugin.UploadFileCondition) (resp plugin.UploadFileResponse) {
	resp = plugin.UploadFileResponse{}
	client, err := oss.New(s.Config.Endpoint, s.Config.AccessKeyID, s.Config.AccessKeySecret)
	if err != nil {
		resp.OriginalError = err
		resp.DisplayErrorMsg = plugin.MakeTranslator(i18n.ErrMisStorageConfig)
		return resp
	}

	bucket, err := client.Bucket(s.Config.BucketName)
	if err != nil {
		resp.OriginalError = fmt.Errorf("get bucket failed: %v", err)
		resp.DisplayErrorMsg = plugin.MakeTranslator(i18n.ErrMisStorageConfig)
		return resp
	}

	file, err := ctx.FormFile("file")
	if err != nil {
		resp.OriginalError = fmt.Errorf("get upload file failed: %v", err)
		resp.DisplayErrorMsg = plugin.MakeTranslator(i18n.ErrFileNotFound)
		return resp
	}

	if s.IsUnsupportedFileType(file.Filename, condition) {
		resp.OriginalError = fmt.Errorf("file type not allowed")
		resp.DisplayErrorMsg = plugin.MakeTranslator(i18n.ErrUnsupportedFileType)
		return resp
	}

	if s.ExceedFileSizeLimit(file.Size, condition) {
		resp.OriginalError = fmt.Errorf("file size too large")
		resp.DisplayErrorMsg = plugin.MakeTranslator(i18n.ErrOverFileSizeLimit)
		return resp
	}

	open, err := file.Open()
	if err != nil {
		resp.OriginalError = fmt.Errorf("get file failed: %v", err)
		resp.DisplayErrorMsg = plugin.MakeTranslator(i18n.ErrFileNotFound)
		return resp
	}
	defer open.Close()

	objectKey := s.createObjectKey(file.Filename, condition.Source)
	request := &oss.PutObjectRequest{
		ObjectKey: objectKey,
		Reader:    open,
	}
	respBody, err := bucket.DoPutObject(request, nil)
	if err != nil {
		resp.OriginalError = fmt.Errorf("upload file failed: %v", err)
		resp.DisplayErrorMsg = plugin.MakeTranslator(i18n.ErrUploadFileFailed)
		return resp
	}
	defer respBody.Close()
	resp.FullURL = s.Config.VisitUrlPrefix + objectKey
	return resp
}

func (s *Storage) createObjectKey(originalFilename string, source plugin.UploadSource) string {
	ext := strings.ToLower(filepath.Ext(originalFilename))
	randomString := s.randomObjectKey()
	switch source {
	case plugin.UserAvatar:
		return s.Config.ObjectKeyPrefix + "avatar/" + randomString + ext
	case plugin.UserPost:
		return s.Config.ObjectKeyPrefix + "post/" + randomString + ext
	case plugin.UserPostAttachment:
		return s.Config.ObjectKeyPrefix + "attachment/" + randomString + ext
	case plugin.AdminBranding:
		return s.Config.ObjectKeyPrefix + "branding/" + randomString + ext
	default:
		return s.Config.ObjectKeyPrefix + "other/" + randomString + ext
	}
}

func (s *Storage) randomObjectKey() string {
	bytes := make([]byte, 4)
	_, _ = rand.Read(bytes)
	return fmt.Sprintf("%d", time.Now().UnixNano()) + hex.EncodeToString(bytes)
}

func (s *Storage) IsUnsupportedFileType(originalFilename string, condition plugin.UploadFileCondition) bool {
	if condition.Source == plugin.AdminBranding || condition.Source == plugin.UserAvatar {
		ext := strings.ToLower(filepath.Ext(originalFilename))
		if _, ok := plugin.DefaultFileTypeCheckMapping[condition.Source][ext]; ok {
			return false
		}
		return true
	}

	// check the post image and attachment file type check
	if condition.Source == plugin.UserPost {
		return checker.IsUnAuthorizedExtension(originalFilename, condition.AuthorizedImageExtensions)
	}
	return checker.IsUnAuthorizedExtension(originalFilename, condition.AuthorizedAttachmentExtensions)
}

func (s *Storage) ExceedFileSizeLimit(fileSize int64, condition plugin.UploadFileCondition) bool {
	if condition.Source == plugin.UserPostAttachment {
		return fileSize > int64(condition.MaxAttachmentSize)*1024*1024
	}
	return fileSize > int64(condition.MaxImageSize)*1024*1024
}

func (s *Storage) ConfigFields() []plugin.ConfigField {
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
			Value: s.Config.Endpoint,
		},
		{
			Name:        "bucket_name",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigBucketNameTitle),
			Description: plugin.MakeTranslator(i18n.ConfigBucketNameDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: s.Config.BucketName,
		},
		{
			Name:        "object_key_prefix",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigObjectKeyPrefixTitle),
			Description: plugin.MakeTranslator(i18n.ConfigObjectKeyPrefixDescription),
			Required:    false,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: s.Config.ObjectKeyPrefix,
		},
		{
			Name:        "access_key_id",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigAccessKeyIdTitle),
			Description: plugin.MakeTranslator(i18n.ConfigAccessKeyIdDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: s.Config.AccessKeyID,
		},
		{
			Name:        "access_key_secret",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigAccessKeySecretTitle),
			Description: plugin.MakeTranslator(i18n.ConfigAccessKeySecretDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: s.Config.AccessKeySecret,
		},
		{
			Name:        "visit_url_prefix",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigVisitUrlPrefixTitle),
			Description: plugin.MakeTranslator(i18n.ConfigVisitUrlPrefixDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: s.Config.VisitUrlPrefix,
		},
	}
}

func (s *Storage) ConfigReceiver(config []byte) error {
	c := &StorageConfig{}
	_ = json.Unmarshal(config, c)
	s.Config = c
	return nil
}
