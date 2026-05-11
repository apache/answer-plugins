# Apache Answer Plugin: Qdrant Vector Search

This plugin enables semantic/vector search in [Apache Answer](https://github.com/apache/answer) using [Qdrant](https://qdrant.tech/).

## Prerequisites

- Qdrant instance (self-hosted or Qdrant Cloud)
- An OpenAI-compatible embedding API (e.g., OpenAI, Azure OpenAI, or any compatible provider)

## Installation

Build Apache Answer with this plugin:

```bash
./answer build --with github.com/apache/answer-plugins/vector-search-qdrant
```

## Configuration

After enabling the plugin in the Admin UI (**Admin > Plugins > Vector Search**), configure the following fields:

| Field | Description | Example |
|---|---|---|
| **Qdrant Endpoint** | Qdrant gRPC endpoint | `localhost:6334` |
| **Qdrant API Key** | API key for Qdrant authentication (optional for local instances) | |
| **Embedding API Host** | OpenAI-compatible API base URL | `https://api.openai.com` |
| **Embedding API Key** | API key for the embedding service | `sk-...` |
| **Embedding Model** | Model name for generating embeddings | `text-embedding-3-small` |
| **Embedding Level** | `question` embeds question + all answers + comments together; `answer` embeds each answer separately | `question` |
| **Similarity Threshold** | Minimum cosine similarity score (0-1). Default `0` means no filtering | `0.5` |

> **Note:** This plugin uses a dual API key pattern -- one for Qdrant authentication and a separate one for the embedding API.

## How It Works

- **Embedding dimensions** are auto-detected from the configured model. No manual dimension configuration is needed.
- On first configuration, the plugin creates a collection `answer_vector_embeddings` with cosine distance metric.
- If the embedding model changes and produces different dimensions, the collection is automatically deleted and recreated.
- Uses deterministic UUIDs derived from object IDs for consistent upsert behavior.
- Communicates with Qdrant via gRPC for high performance.
- A full sync of all questions/answers is triggered when the plugin starts.

## Running Qdrant Locally

Using Docker:

```bash
docker run -p 6333:6333 -p 6334:6334 qdrant/qdrant
```

The gRPC endpoint will be `localhost:6334` and the REST API at `localhost:6333`.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
