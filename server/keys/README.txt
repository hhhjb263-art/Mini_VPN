# 密钥目录

把以下密钥文件放到本目录（**绝不**提交到 Git 仓库）：

- `server.key`  服务端 X25519 私钥（敏感，绝不入库）
- `server.pub`  服务端公钥（可提供给客户端）
- `client.pub`  客户端公钥（备用）

私钥请用 `scp` 等安全方式从本地传输到服务器：

```bash
scp keys/server.key user@服务器IP:/path/server/keys/
```

服务端运行时通过 `-k` 参数指定私钥路径，默认 `keys/server.key`。
