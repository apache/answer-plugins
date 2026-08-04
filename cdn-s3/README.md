# CDN With S3 Storage (preview)
> This plugin can be used to store static files to AWS S3.

## How to use

### Build
```bash
./answer build --with github.com/answerdev/plugins/cdn-s3
```

### Configuration
- `Endpoint` -  Endpoint of the AWS S3 storage
- `Bucket Name` - Your bucket name
- `Object Key Prefix` - Prefix of the object key like 'static/' that ending with '/'
- `Access Key Id` - AccessKeyId of the S3
- `Access Key Secret` - AccessKeySecret of the S3
- `Access Token` - AccessToken of the S3
- `Visit Url Prefix` - Prefix of access address for the static file, ending with '/' such as https://static.example.com/xxx/
- `Max File Size` - Max file size in MB, default is 10MB

### Notes

#### CORS

A `type="module"` script is always fetched in CORS mode. If `Visit Url Prefix` points at a different origin than the site itself, the bucket must return `Access-Control-Allow-Origin` for that origin, or the browser blocks the script and the page loads with no JavaScript.

Add a CORS configuration to the bucket (S3 console, Permissions tab, or the `PutBucketCors` API). A minimal rule that lets the site read static assets, no credentials required:

```json
[
  {
    "AllowedOrigins": ["https://your-answer-site.example.com"],
    "AllowedMethods": ["GET"],
    "AllowedHeaders": [],
    "ExposeHeaders": []
  }
]
```

Replace `https://your-answer-site.example.com` with the origin the site is actually served from.

If `Visit Url Prefix` points at a CloudFront distribution in front of the bucket rather than the bucket directly, the bucket's CORS rule alone is not enough. CloudFront only forwards the browser's `Origin` header to S3, and only caches per origin, when its cache or origin request policy says to; otherwise it can cache one origin's CORS response and serve it to every other origin. Either attach the managed origin request policy `CORS-S3Origin` (or a custom policy that includes `Origin` in the cache key) so CloudFront forwards and caches per origin, or attach a response headers policy with its own CORS configuration so CloudFront adds `Access-Control-Allow-Origin` itself at the edge.