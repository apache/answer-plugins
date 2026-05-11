# Apache Answer Plugin: ChromaDB Vector Search

This plugin enables semantic/vector search in [Apache Answer](https://github.com/apache/answer) using [ChromaDB](https://www.trychroma.com/).

## Prerequisites

- ChromaDB instance (self-hosted)
- An OpenAI-compatible embedding API (e.g., OpenAI, Azure OpenAI, or any compatible provider)

## Installation

Build Apache Answer with this plugin:

```bash
./answer build --with github.com/apache/answer-plugins/vector-search-chromadb
```

## Configuration

After enabling the plugin in the Admin UI (**Admin > Plugins > Vector Search**), configure the following fields:

| Field | Description | Example |
|---|---|---|
| **ChromaDB Endpoint** | ChromaDB HTTP API URL | `http://localhost:8000` |
| **Embedding API Host** | OpenAI-compatible API base URL | `https://api.openai.com` |
| **Embedding API Key** | API key for the embedding service | `sk-...` |
| **Embedding Model** | Model name for generating embeddings | `text-embedding-3-small` |
| **Embedding Level** | `question` embeds question + all answers + comments together; `answer` embeds each answer separately | `question` |
| **Similarity Threshold** | Minimum cosine similarity score (0-1). Default `0` means no filtering | `0.5` |

## How It Works

- **Embedding dimensions** are auto-detected from the configured model. No manual dimension configuration is needed.
- On first configuration, the plugin creates a collection `answer_vector_embeddings` with `hnsw:space` set to cosine.
- Uses the ChromaDB REST API directly (no external Go SDK required).
- ChromaDB cosine distance (0 = identical, 2 = opposite) is converted to a similarity score (1.0 = identical, 0.0 = opposite).
- A full sync of all questions/answers is triggered when the plugin starts.

## Running ChromaDB Locally

Using Docker:

```bash
docker run -p 8000:8000 chromadb/chroma
```

The REST API will be available at `http://localhost:8000`.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
