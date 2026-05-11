# Apache Answer Plugin: Weaviate Vector Search

This plugin enables semantic/vector search in [Apache Answer](https://github.com/apache/answer) using [Weaviate](https://weaviate.io/).

## Prerequisites

- Weaviate instance (self-hosted or Weaviate Cloud)
- An OpenAI-compatible embedding API (e.g., OpenAI, Azure OpenAI, or any compatible provider)

## Installation

Build Apache Answer with this plugin:

```bash
./answer build --with github.com/apache/answer-plugins/vector-search-weaviate
```

## Configuration

After enabling the plugin in the Admin UI (**Admin > Plugins > Vector Search**), configure the following fields:

| Field | Description | Example |
|---|---|---|
| **Weaviate Endpoint** | Weaviate server URL | `http://localhost:8080` |
| **Weaviate API Key** | API key for Weaviate authentication (optional for local instances) | |
| **Embedding API Host** | OpenAI-compatible API base URL | `https://api.openai.com` |
| **Embedding API Key** | API key for the embedding service | `sk-...` |
| **Embedding Model** | Model name for generating embeddings | `text-embedding-3-small` |
| **Embedding Level** | `question` embeds question + all answers + comments together; `answer` embeds each answer separately | `question` |
| **Similarity Threshold** | Minimum cosine similarity score (0-1). Default `0` means no filtering | `0.5` |

> **Note:** This plugin uses a dual API key pattern -- one for Weaviate authentication and a separate one for the embedding API.

## How It Works

- Weaviate handles vector dimensions automatically via its `vectorizer: none` configuration, so no manual dimension setup is needed.
- On first configuration, the plugin creates a class `AnswerVector` with cosine distance metric.
- Uses deterministic UUIDs derived from object IDs for consistent upsert behavior.
- A full sync of all questions/answers is triggered when the plugin starts.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
