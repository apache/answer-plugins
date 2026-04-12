# Apache Answer Plugin: In-Memory Vector Search

A lightweight, pure-Go, in-memory vector search plugin for [Apache Answer](https://github.com/apache/answer). Designed for **development and testing** -- no external services, no Docker, no CGo required.

## When to Use This Plugin

- **Development** -- quickly test semantic search without setting up a database
- **Testing** -- verify vector search integration in CI/CD pipelines
- **Small demos** -- run Answer with vector search on a single machine with zero setup

**Not recommended for production** -- all data is stored in memory and lost on restart.

## Installation

Build Apache Answer with this plugin:

```bash
./answer build --with github.com/apache/answer-plugins/vector-search-memory
```

No special environment variables needed. Works with `CGO_ENABLED=0`.

## Configuration

After enabling the plugin in the Admin UI (**Admin > Plugins > Vector Search**), configure the following fields:

| Field | Description | Example |
|---|---|---|
| **Embedding API Host** | OpenAI-compatible API base URL | `https://api.openai.com` |
| **Embedding API Key** | API key for the embedding service | `sk-...` |
| **Embedding Model** | Model name for generating embeddings | `text-embedding-3-small` |
| **Embedding Level** | `question` embeds question + all answers + comments together; `answer` embeds each answer separately | `question` |
| **Similarity Threshold** | Minimum cosine similarity score (0-1). Default `0` means no filtering | `0.5` |

No connection endpoint or database path is needed -- everything runs in-process.

## How It Works

- Stores all document embeddings in a Go `map[string]*document` guarded by `sync.RWMutex`
- Search performs brute-force cosine similarity over all stored vectors
- Embedding dimensions are auto-detected from the configured model
- Changing the embedding model clears all stored documents (since dimensions may differ)
- A full sync of all questions/answers is triggered when the plugin starts

## Limitations

- **No persistence** -- data is lost when Answer restarts
- **No scalability** -- brute-force search is O(n) per query; suitable for thousands of documents, not millions
- **Memory usage** -- each document stores a full embedding vector in RAM

For production use, consider [pgvector](../vector-search-pgvector/), [Elasticsearch](../vector-search-elasticsearch/), [Weaviate](../vector-search-weaviate/), [Milvus](../vector-search-milvus/), [Qdrant](../vector-search-qdrant/), or [ChromaDB](../vector-search-chromadb/).

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
