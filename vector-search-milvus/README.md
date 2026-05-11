# Apache Answer Plugin: Milvus Vector Search

This plugin enables semantic/vector search in [Apache Answer](https://github.com/apache/answer) using [Milvus](https://milvus.io/).

## Prerequisites

- Milvus 2.x instance (self-hosted or Zilliz Cloud)
- An OpenAI-compatible embedding API (e.g., OpenAI, Azure OpenAI, or any compatible provider)

## Installation

Build Apache Answer with this plugin:

```bash
./answer build --with github.com/apache/answer-plugins/vector-search-milvus
```

## Configuration

After enabling the plugin in the Admin UI (**Admin > Plugins > Vector Search**), configure the following fields:

| Field | Description | Example |
|---|---|---|
| **Milvus Endpoint** | Milvus gRPC endpoint | `localhost:19530` |
| **Embedding API Host** | OpenAI-compatible API base URL | `https://api.openai.com` |
| **Embedding API Key** | API key for the embedding service | `sk-...` |
| **Embedding Model** | Model name for generating embeddings | `text-embedding-3-small` |
| **Embedding Level** | `question` embeds question + all answers + comments together; `answer` embeds each answer separately | `question` |
| **Similarity Threshold** | Minimum cosine similarity score (0-1). Default `0` means no filtering | `0.5` |

## How It Works

- **Embedding dimensions** are auto-detected from the configured model. No manual dimension configuration is needed.
- On first configuration, the plugin creates a collection `answer_vector_embeddings` with VarChar fields and a FloatVector field.
- An IvfFlat index with cosine metric is created on the embedding field.
- If the embedding model changes and produces different dimensions, the collection is automatically dropped and recreated.
- Upsert is implemented via delete-by-expression + insert (Milvus v2 pattern).
- A full sync of all questions/answers is triggered when the plugin starts.

## Running Milvus Locally

Using Docker Compose:

```bash
# Download the docker-compose file
wget https://github.com/milvus-io/milvus/releases/download/v2.4.0/milvus-standalone-docker-compose.yml -O docker-compose.yml

# Start Milvus
docker compose up -d
```

The default gRPC endpoint will be `localhost:19530`.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
