# Apache Answer Official Plugins

Apache Answer Official Plugins are built to enhance the feature of [Answer](https://github.com/apache/answer).

[![LICENSE](https://img.shields.io/github/license/apache/answer)](https://github.com/apache/answer/blob/main/LICENSE)
[![Language](https://img.shields.io/badge/language-go-blue.svg)](https://golang.org/)
[![Language](https://img.shields.io/badge/language-react-blue.svg)](https://reactjs.org/)
[![Go Report Card](https://goreportcard.com/badge/github.com/apache/answer)](https://goreportcard.com/report/github.com/apache/answer)
[![Discord](https://img.shields.io/badge/discord-chat-5865f2?logo=discord&logoColor=f5f5f5)](https://discord.gg/Jm7Y4cbUej)

## Types of plugin

Our plugin is under development and the interface definition of the plugin can be viewed at [this link](https://github.com/apache/answer/tree/main/plugin).

### Connector

The Connector plugin helps us to implement third-party login functionality. For example: Google or GitHub OAuth login.

- [x] [OAuth2 Basic](https://github.com/apache/answer-plugins/tree/main/connector-basic)
- [x] [GitHub](https://github.com/apache/answer-plugins/tree/main/connector-github)
- [x] [Google](https://github.com/apache/answer-plugins/tree/main/connector-google)
- [x] [Dingtalk](https://github.com/apache/answer-plugins/tree/main/connector-dingtalk)

### Storage

The Storage plugin helps us to upload files to third-party storage. For example: Aliyun OSS or AWS S3.

- [x] [Aliyun OSS](https://github.com/apache/answer-plugins/tree/main/storage-aliyunoss)
- [x] [Tencentyun COS](https://github.com/apache/answer-plugins/tree/main/storage-tencentyuncos)
- [x] [S3](https://github.com/apache/answer-plugins/tree/main/storage-s3)

### Cache

Using the Cache plugin allows you to store cached data in a different location. For example: Redis or Memcached.

- [x] [Redis](https://github.com/apache/answer-plugins/tree/main/cache-redis)

### Search

Support using search plugin to speed up the search of question answers. For example: Elasticsearch or Meilisearch.

- [x] [Elasticsearch](https://github.com/apache/answer-plugins/tree/main/search-elasticsearch)
- [x] [Meilisearch](https://github.com/apache/answer-plugins/tree/main/search-meilisearch)
- [x] [Algolia](https://github.com/apache/answer-plugins/tree/main/search-algolia)

### User Center

Using the third-party user system to manage users. For example: WeCom

- [x] [WeCom](https://github.com/apache/answer-plugins/tree/main/user-center-wecom)

### Notification

The Notification plugin helps us to send messages to third-party notification systems. For example: Slack.

- [x] [Slack](https://github.com/apache/answer-plugins/tree/main/notification-slack)
- [x] [Lark](https://github.com/apache/answer-plugins/tree/main/notification-lark)
- [x] [Ding talk](https://github.com/apache/answer-plugins/tree/main/notification-dingtalk)
- [x] [WeCom](https://github.com/apache/answer-plugins/tree/main/notification-wecom)

### Sidebar

Customize the sidebar tags or link.

- [x] [Quicklinks](https://github.com/apache/answer-plugins/tree/main/quick-links)

### Route

Support for custom routing.

### Editor

Support for extending the markdown editor's toolbar.

- [x] [chart](https://github.com/apache/answer-plugins/tree/main/editor-chart)
- [x] [formula](https://github.com/apache/answer-plugins/tree/main/editor-formula)
- [x] [embed](https://github.com/apache/answer-plugins/tree/main/editor-embed)

### Reviewer

Support for customizing the reviewer.

- [x] [default](https://github.com/apache/answer-plugins/tree/main/reviewer-basic)
- [x] [akismet](https://github.com/apache/answer-plugins/tree/main/reviewer-akismet)

### Filter (coming soon)

### Render (coming soon)

### Exporter (coming soon)

### Importer (coming soon)

## How to build the Answer with your need plugins?

Learn more about the plugin, please visit our [docs](https://answer.apache.org/docs/plugins).

## Build Docker Image with plugins
Building the Answer docker image with plugins is easy, see [here](https://answer.apache.org/docs/plugins/#build-docker-image-with-plugin-from-answer-base-image).
