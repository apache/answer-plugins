# S3 Storage
> This plugin can be used to store attachments and avatars to AWS S3.

## How to use

### Build
```bash
./answer build --with github.com/apache/answer-plugins/storage-s3
```

### Configuration
- `Endpoint` -  Endpoint of the AWS S3 storage
- `Bucket Name` - Your bucket name
- `Object Key Prefix` - Prefix of the object key like 'answer/data/' that ending with '/'
- `Access Key Id` - AccessKeyId of the S3
- `Access Key Secret` - AccessKeySecret of the S3
- `Access Token` - AccessToken of the S3
- `Visit Url Prefix` - Prefix of access address for the uploaded file, ending with '/' such as https://example.com/xxx/