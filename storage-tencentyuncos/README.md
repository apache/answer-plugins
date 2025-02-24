# Tencent COS Storage

> This plugin can be used to store attachments and avatars to Tencent COS.

## How to use

### Build

```bash
./answer build --with github.com/apache/answer-plugins/storage-tencentyuncos
```

### Configuration

- `Region` - Region of Tencent COS storage, like 'ap-beijing'
- `Bucket Name` - Your bucket name
- `Object Key Prefix` - Prefix of the object key like 'answer/data/' that ending with '/'
- `Secret ID` - Secret ID of the Tencent COS storage
- `Secret Key` - Secret Key of the Tencent COS storage
- `Visit Url Prefix` - Prefix of access address for the uploaded file, ending with '/' such as https://example.com/xxx/
