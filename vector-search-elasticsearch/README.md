# Apache Answer Plugin: Elasticsearch Vector Search

This plugin enables semantic/vector search in [Apache Answer](https://github.com/apache/answer) using [Elasticsearch](https://www.elastic.co/elasticsearch/) with dense vector fields.

## Prerequisites

- Elasticsearch 8.0+ (with dense vector and kNN search support)
- An OpenAI-compatible embedding API (e.g., OpenAI, Azure OpenAI, or any compatible provider)

## Installation

Build Apache Answer with this plugin:

```bash
./answer build --with github.com/apache/answer-plugins/vector-search-elasticsearch
```

## Configuration

After enabling the plugin in the Admin UI (**Admin > Plugins > Vector Search**), configure the following fields:

| Field | Description | Example |
|---|---|---|
| **Endpoints** | Comma-separated Elasticsearch URLs | `http://localhost:9200` |
| **Username** | Elasticsearch username (optional) | `elastic` |
| **Password** | Elasticsearch password (optional) | `changeme` |
| **Embedding API Host** | OpenAI-compatible API base URL | `https://api.openai.com` |
| **Embedding API Key** | API key for the embedding service | `sk-...` |
| **Embedding Model** | Model name for generating embeddings | `text-embedding-3-small` |
| **Embedding Level** | `question` embeds question + all answers + comments together; `answer` embeds each answer separately | `question` |
| **Similarity Threshold** | Minimum cosine similarity score (0-1). Default `0` means no filtering | `0.5` |

## How It Works

- **Embedding dimensions** are auto-detected from the configured model. No manual dimension configuration is needed.
- On first configuration, the plugin creates an index `answer_vector` with a `dense_vector` field matching the detected dimensions and cosine similarity.
- If the embedding model changes and produces different dimensions, the index is automatically deleted and recreated.
- Uses Elasticsearch kNN search for vector similarity queries.
- A full sync of all questions/answers is triggered when the plugin starts.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
