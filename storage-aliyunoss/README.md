# Aliyun OSS Storage
> This plugin can be used to store attachments and avatars to Aliyun OSS.

## How to use

### Build
```bash
./answer build --with github.com/apache/answer-plugins/storage-aliyunoss
```

### Configuration
- `Endpoint` - Endpoint of AliCloud OSS storage, such as oss-cn-hangzhou.aliyuncs.com
- `Bucket Name` - Your bucket name
- `Object Key Prefix` - Prefix of the object key like 'answer/data/' that ending with '/'
- `Access Key Id` - AccessKeyID of the AliCloud OSS storage
- `Access Key Secret` - AccessKeySecret of the AliCloud OSS storage
- `Visit Url Prefix` - Prefix of access address for the uploaded file, ending with '/' such as https://example.com/xxx/