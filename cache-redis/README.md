# Redis Cache (preview)
> This plugin designed to support Redis cache.

## How to use

### Build
```bash
./answer build --with github.com/apache/answer-plugins/cache-redis
```

### Configuration
- `Endpoint` - Redis connection address
- `Username` - Redis username
- `Password` - Redis password
- `TLS` - Enable TLS when connecting to Redis
- `Skip TLS Verify` - Skip TLS certificate verification (insecure, not recommended for production)
