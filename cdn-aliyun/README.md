# CDN With Aliyun OSS Storage (preview)
> This plugin can be used to store static files to Aliyun OSS.

## How to use

### Build
```bash
./answer build --with github.com/apache/answer-plugins/cdn-aliyun
```

### Configuration
- `Endpoint` -  Endpoint of AliCloud OSS storage, such as oss-cn-hangzhou.aliyuncs.com
- `Bucket Name` - Your bucket name
- `Object Key Prefix` - Prefix of the object key like 'static/' that ending with '/'
- `Access Key Id` - AccessKeyID of the AliCloud OSS storage
- `Access Key Secret` - AccessKeySecret of the AliCloud OSS storage
- `Visit Url Prefix` - Prefix of access address for the CDN file, ending with '/' such as https://static.example.com/xxx/
- `Max File Size` - Max file size in MB, default is 10MB

### Notes

#### CORS

A `type="module"` script is always fetched in CORS mode. If `Visit Url Prefix` points at a different origin than the site itself, the bucket must return `Access-Control-Allow-Origin` for that origin, or the browser blocks the script and the page loads with no JavaScript.

Add a CORS rule to the bucket (OSS console CORS settings, `ossutil`, or the `PutBucketCors` API). A minimal rule that lets the site read static assets, no credentials required:

```xml
<CORSConfiguration>
  <CORSRule>
    <AllowedOrigin>https://your-answer-site.example.com</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedHeader>*</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader>
    <MaxAgeSeconds>3600</MaxAgeSeconds>
  </CORSRule>
</CORSConfiguration>
```

Replace `https://your-answer-site.example.com` with the origin the site is actually served from. `GET` is the only method this plugin needs, and no `Access-Control-Allow-Credentials` handling is required since the request carries no cookies or auth headers.