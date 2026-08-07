# VDS Account Connector

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

VDS账户连接器是Apache Answer的官方OAuth连接器，与VDS账户系统集成，提供无缝的单点登录（SSO）功能。

## 简介

VDS Account Connector 允许用户通过他们的VDS账户直接登录到Apache Answer社区。该连接器完全遵循VDS官方OAuth 2.0标准实现，所有复杂的平台细节（签名管理、端点配置）都已自动化处理。

## 功能特性

- ✅ **完整OAuth 2.0实现** - VDS官方OAuth 2.0标准支持
- ✅ **零配置端点** - VDS全球端点（open-global.vdsentnet.com）已硬编码
- ✅ **自动签名管理** - 平台签名自动获取、缓存、刷新，无需用户干预
- ✅ **自动用户信息提取** - 自动解析VDS API响应
- ✅ **开箱即用Logo** - 内置官方EM Logo，无需额外配置
- ✅ **国际化支持** - 中英文多语言支持
- ✅ **错误恢复** - 智能重试机制，自动处理网络异常

## 安装

1. 克隆或下载VDS连接器
2. 将文件夹复制到Apache Answer plugins目录
3. 重新编译或重启Apache Answer服务

## 配置

### 前置条件

在配置此连接器之前，你需要：

1. **VDS开发者账户** - 在[VDS开发者平台](https://developer.vds.pub/)注册
2. **创建应用** - 创建一个新应用以获得：
   - `Client ID` - 应用ID（vap_xxxx格式）
   - `Client Secret` - 应用密钥
3. **配置回调URL** - 在应用设置中配置OAuth回调地址

### 配置参数

VDS连接器采用极简配置方案，只需要2个参数。所有VDS特定配置（端点、签名、Logo）都已自动处理：

| 参数 | 必需 | 说明 |
|-----|------|------|
| **Client ID** | ✅ | VDS应用ID（vap_xxxx格式），从VDS开发者平台获得 |
| **Client Secret** | ✅ | VDS应用密钥，从VDS开发者平台获得 |

**注意**：平台签名（Platform Signature）由连接器自动在运行时获取和管理，无需用户手动配置。

## 自动管理的功能

### 平台签名（Platform Signature）管理
连接器自动处理VDS平台签名的获取和刷新：

- **自动获取** — 在首次使用时自动调用VDS `/api/auth/token` 端点获取平台签名
- **智能缓存** — 签名缓存在内存中，避免重复请求
- **自动刷新** — 当签名即将过期（剩余时间<3分钟）时自动换新
- **错误恢复** — 失败时自动重试（最多3次），采用指数退避策略
- **线程安全** — 使用互斥锁确保并发访问安全

### Logo处理
连接器内置官方EM Logo，支持两种工作模式：

- **自动模式** — 首次加载时自动读取嵌入的 EMlogo-large1x.png，转换为 base64 DataURI，缓存使用
- **初始化缓存** — 配置接收后立即生成并缓存 Logo DataURI，避免每次请求都转换

## VDS OAuth 流程

此连接器遵循VDS官方OAuth流程，所有端点已自动配置：

### 1. 授权请求
用户被重定向到VDS授权页面：
```
GET https://account.vds.pub/authorize?
  client_id=vap_xxxxx&
  redirect_uri=YOUR_CALLBACK_URL&
  response_type=code&
  scope=openid,profile&
  state=RANDOM_STATE
```

### 2. 获取授权码
用户授权后，VDS回跳到回调URL：
```
YOUR_CALLBACK_URL?code=AUTH_CODE&state=RANDOM_STATE
```

### 3. 交换Access Token（已自动处理）
后端使用授权码交换access token。连接器自动处理平台签名注入：
```
POST https://open-global.vdsentnet.com/api/proxy/account/sso/token
Authorization: Bearer <platform_signature>  (自动管理)
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=YOUR_CALLBACK_URL&
client_id=vap_xxxxx&
client_secret=YOUR_APP_SECRET
```

### 4. 获取用户信息（已自动处理）
使用access token从VDS服务器获取用户信息：
```
GET https://open-global.vdsentnet.com/api/proxy/account/sso/userinfo
Authorization: Bearer <platform_signature>  (自动管理)
X-OAuth-Access-Token: <access_token>
```

响应示例：
```json
{
  "sub": "10001",
  "name": "示例用户",
  "username": "example_user",
  "email": "user@example.com",
  "avatar_url": "https://...",
  "phone_number": "+86137****8072",
  "updated_at": 1774002667
}
```

### 自动化工作流时序

```
用户授权
  │
  ├─→ ConnectorSender: 生成授权URL
  │
  └─→ [VDS授权服务]
       │
       └─→ ConnectorReceiver: 接收回调
             │
             ├─→ exchangeCodeForToken()
             │    ├─→ getPlatformSignature() [自动获取/刷新]
             │    └─→ 交换OAuth Token
             │
             └─→ getUserInfo()
                  ├─→ getPlatformSignature() [检查缓存]
                  └─→ 获取用户信息并返回
```

## 硬编码配置

以下VDS特定配置已固定在代码中，无需手动修改：

**OAuth端点：**
- 授权端点: `https://account.vds.pub/authorize`
- Token交换: `https://open-global.vdsentnet.com/api/proxy/account/sso/token`
- 签名交换: `https://open-global.vdsentnet.com/api/auth/token`
- 用户信息: `https://open-global.vdsentnet.com/api/proxy/account/sso/userinfo`

**用户信息字段映射：**
| Answer字段 | VDS API字段 | JSON路径 |
|-----------|----------|---------|
| ExternalID | User ID | `sub` |
| DisplayName | 昵称 | `name` |
| Username | 用户名 | `username` |
| Email | 邮箱 | `email` |
| Avatar | 头像 | `avatar_url` |

**OAuth范围：** `openid,profile`

## API文档

关于VDS OAuth实现的详细信息，参考官方文档：

- [VDS账户快速接入（OAuth）](https://developer.vds.pub/docs?path=VDS%E8%B4%A6%E6%88%B7&name=VDS%E8%B4%A6%E6%88%B7%E5%BF%AB%E9%80%9F%E6%8E%A5%E5%85%A5%EF%BC%88OAuth%EF%BC%89)
- [授权端点](https://developer.vds.pub/docs?path=VDS%E8%B4%A6%E6%88%B7&name=%E6%8E%88%E6%9D%83%E7%AB%AF%E7%82%B9%EF%BC%88Authorize%EF%BC%8Caccount.sso.authorize%EF%BC%89)
- [Token交换端点](https://developer.vds.pub/docs?path=VDS%E8%B4%A6%E6%88%B7&name=%E7%AD%BE%E5%90%8D%E4%BA%A4%E6%8D%A2%E7%AB%AF%E7%82%B9%EF%BC%88Token%EF%BC%8Caccount.sso.token%EF%BC%89)
- [用户信息端点](https://developer.vds.pub/docs?path=VDS%E8%B4%A6%E6%88%B7&name=%E7%94%A8%E6%88%B7%E4%BF%A1%E6%81%AF%E7%AB%AF%E7%82%B9%EF%BC%88UserInfo%EF%BC%8Caccount.sso.userinfo%EF%BC%89)

## 故障排查

### 1. "无法获取平台签名" 错误
**原因：** 连接器无法调用VDS `/api/auth/token` 端点或连接器凭证不正确

**解决方案：**
- 验证 Client ID 和 Client Secret 的正确性（从VDS开发者平台复制）
- 检查网络连接，确保能访问 `open-global.vdsentnet.com`
- 查看日志中的详细错误信息，确认是否重试3次后仍失败
- 确认VDS应用在开发者平台未被停用

### 2. "授权码无效或重定向URI不匹配"
**原因：** 回调URL配置不一致

**解决方案：**
- 确保Apache Answer的回调URL（redirect_uri）与VDS应用配置中的回调地址完全匹配
- 检查URL是否包含正确的协议前缀（http://或https://）
- 验证URL是否正确编码（不应包含特殊字符）

### 3. "用户信息获取失败"
**原因：** VDS API请求失败或响应格式异常

**解决方案：**
- 平台签名由连接器自动管理，无需手动干预
- 检查 Access Token 是否有效且未过期
- 确认VDS API端点可访问
- 查看日志中的HTTP状态码，根据错误代码排查

### 4. Logo不显示
**原因：** 嵌入的Logo文件损坏或加载失败

**解决方案：**
- 连接器使用内置的 EMlogo-large1x.png，已自动转换为 base64 DataURI
- 检查浏览器控制台是否有报错
- 若Logo无法正常显示，检查 assets/EMlogo-large1x.png 文件是否存在且完整
- 重新编译插件

### 5. "性能问题 - 每次请求都很慢"
**原因：** Platform signature缓存未生效或频繁刷新

**解决方案：**
- 连接器自动缓存平台签名，首次获取后无需再次请求（除非即将过期）
- 刷新周期为：签名有效期 - 3分钟
- 检查日志中是否频繁出现"Successfully obtained platform signature"消息
- 若频繁出现，可能是时间同步问题，检查服务器时间是否正确

## 版本历史

### v2.0.0 (2026-03-30)
**主要变更：**
- ✨ **自动平台签名管理** - 无需用户配置，连接器自动获取、缓存、刷新签名
- ✨ **简化配置** - 从4个参数减少到2个（仅需client_id和client_secret）
- ✨ **内置Logo** - 使用官方EM Logo，自动转换为DataURI，无需额外配置
- 🔧 **智能重试** - 失败自动重试最多3次，支持指数退避
- 🔧 **线程安全** - 使用互斥锁保护缓存，支持并发请求
- 📝 **详细日志** - 增加Debug和Info级日志便于问题诊断
- 🐛 **代码清理** - 删除冗余代码，简化实现逻辑

**破坏性变更：**
- 不再需要配置 `platform_signature` 参数
- 不再需要配置 `logo_svg` 参数
- 若从v1.x升级，需要删除这两个旧配置项

### v1.0.0
- 首次发布
- 基础OAuth支持
- 用户配置platform_signature和logo_svg

## 开发

### 编译
```bash
go mod download
go build
```

### 测试
```bash
go test ./...
```

## 许可证

此项目采用Apache License 2.0许可证。详见[LICENSE](LICENSE)文件。

## 支持

如有问题或建议，请：
- 访问[VDS开发者平台](https://developer.vds.pub/)获取官方支持
- 提交Issue到项目仓库

## 更新日志

### v1.1.0 (2026-03-31)
- 🎯 **大幅简化配置** - 从15个字段简化到仅4个必需字段
- 🔒 **硬编码VDS端点** - 确保始终连接到正确的VDS服务器
- 🛡️ **移除邮箱验证检查** - 简化用户信息处理流程
- 🎨 **改进Logo处理** - 支持PNG base64和SVG格式
- 📝 **优化代码结构** - 提高代码可维护性和清晰度

### v1.0.0 (2026-03-30)
- 初始版本发布
- OAuth 2.0完整实现
- VDS用户信息端点集成
- 国际化支持（中文/英文）
- JSON路径灵活映射