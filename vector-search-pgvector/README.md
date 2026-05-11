# Apache Answer Plugin: pgvector Vector Search

This plugin enables semantic/vector search in [Apache Answer](https://github.com/apache/answer) using [PostgreSQL](https://www.postgresql.org/) with the [pgvector](https://github.com/pgvector/pgvector) extension.

## Prerequisites

- PostgreSQL 12+ with the [pgvector](https://github.com/pgvector/pgvector) extension installed
- An OpenAI-compatible embedding API (e.g., OpenAI, Azure OpenAI, or any compatible provider)

## Installation

Build Apache Answer with this plugin:

```bash
./answer build --with github.com/apache/answer-plugins/vector-search-pgvector
```

## Configuration

After enabling the plugin in the Admin UI (**Admin > Plugins > Vector Search**), configure the following fields:

| Field | Description | Example |
|---|---|---|
| **DSN** | PostgreSQL connection string | `postgres://user:pass@localhost:5432/answer?sslmode=disable` |
| **Embedding API Host** | OpenAI-compatible API base URL | `https://api.openai.com` |
| **Embedding API Key** | API key for the embedding service | `sk-...` |
| **Embedding Model** | Model name for generating embeddings | `text-embedding-3-small` |
| **Embedding Level** | `question` embeds question + all answers + comments together; `answer` embeds each answer separately | `question` |
| **Similarity Threshold** | Minimum cosine similarity score (0-1). Default `0` means no filtering | `0.5` |

## How It Works

- **Embedding dimensions** are auto-detected from the configured model. No manual dimension configuration is needed.
- On first configuration, the plugin creates a table `answer_vector_embeddings` with a `vector` column matching the detected dimensions.
- If the embedding model changes and produces different dimensions, the table is automatically dropped and recreated.
- Uses cosine similarity (`<=>` operator) for vector search.
- A full sync of all questions/answers is triggered when the plugin starts.

## Database Setup

Ensure the pgvector extension is installed in your PostgreSQL database:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
