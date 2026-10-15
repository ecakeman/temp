# Banner 指纹识别

用规则匹配一批扫描记录里的 banner，输出协议、软件、版本和置信度。Server 提供 HTTP 接口，Client 读取本地 JSON 并打印结果。识别规则在 `rules/rules.json`，不写在 HTTP Handler 里。

## 架构

```text
Client --POST /fingerprint--> Server --规则引擎--> JSON 数组
                              |
                              +--GET /health
```

请求体是 JSON 数组，不能包在别的对象里：

```json
[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]
```

响应同样是数组，顺序与输入一致。每条包含 `ip`、`port`、`protocol`、`product`、`version`、`os_hint`、`confidence`。认不出来时 `protocol` 为 `unknown`，其余字符串为空，`confidence` 为 0。空数组返回 `[]`。

非法 JSON、缺字段、端口不在 1 到 65535、超过 1 MiB 的请求体、以及数组后面的多余数据会返回 HTTP 错误，不会当成识别结果。

## 目录

| 路径 | 作用 |
| --- | --- |
| `cmd/server` | HTTP 服务。子命令 `health` 请求 `/health`，失败时以非零状态退出 |
| `cmd/client` | 读取 JSON 文件并调用 Server |
| `internal/api` | 请求校验和响应编码 |
| `internal/fingerprint` | Banner 归一化与规则匹配 |
| `internal/model` | 输入输出结构 |
| `rules/rules.json` | 识别规则 |
| `testdata/input.json` | 20 条自测数据，不是 Client 的硬编码输入 |

## 规则

规则按文件中的优先级竞争，数值大的优先。端口只在优先级相同的时候打破平局，服务跑在非默认端口也会匹配。产品规则高于只判断协议的规则。

字段：

- `name`：唯一名称
- `priority`：越大越优先
- `pattern`：Go 正则，可用 `(?P<name>...)` 命名捕获
- `ports`：可选端口提示，不是硬条件
- `protocol`、`product`：命中后写入结果；`product` 可为空
- `version_group`、`os_hint_group`：对应捕获组，省略表示该字段留空
- `confidence`：0 到 1。配置超出范围、正则无法编译或捕获组不存在时，进程启动失败

增加产品时追加一条规则即可，不用改匹配循环。文本形式的 `\xNN`、`\r`、`\n` 会先解码；已经是真实控制字节的 TLS 头和 MySQL 握手不会被删掉。

自测数据覆盖 OpenSSH、nginx、Apache、Jetty、Microsoft-IIS、MySQL 5.7/8.0、Redis（`+PONG`、`-NOAUTH`、`-ERR`）、ProFTPD、vsFTPd、Pure-FTPd、TLS 记录头，以及不能当作 FTP 的 `QUIT`。没有 `Server` 头但有 HTTP 状态行时，协议仍是 `HTTP`，产品为空，置信度低于带软件名的规则。

限制：这不是完整的服务探测库。SMTP 的 `220` 问候不会仅凭状态码被标成 FTP。未知软件的 HTTP 响应只会落到协议层。Redis 响应通常没有版本，版本字段保持为空。

## Docker Compose

构建并启动 Server：

```bash
docker compose up --build -d
```

Server 在容器内监听 `8080`，宿主机只绑定 `127.0.0.1:8080`。健康检查由镜像里的 `/server health` 发起真实 HTTP 请求，不依赖 shell 或 curl。Client 使用 profile，不会在普通 `up` 时自动跑完退出。

```bash
curl http://127.0.0.1:8080/health
docker compose --profile client run --rm client
docker compose down
```

Client 通过网络名访问 `http://server:8080`。两个容器都是非 root、只读根文件系统、丢弃全部 capabilities，并设置了 `no-new-privileges`。

换输入文件时，把新的 JSON 数组挂到 Client 的 `/data/input.json`，或先改 `testdata/input.json` 再运行上面的 Client 命令。换规则时编辑 `rules/rules.json`。Compose 把该文件只读挂到 `/rules/rules.json`，改完后重启 Server：

```bash
docker compose up -d --force-recreate server
```

本机不用容器时：

```bash
set RULES_PATH=rules/rules.json
go run ./cmd/server
go run ./cmd/client -file testdata/input.json -server http://127.0.0.1:8080
```

`SERVER_URL` 可以代替 `-server`。

## 检查

```bash
gofmt -l .
go test ./...
go vet ./...
docker compose config
```

推送到 `main` 后，GitHub Actions 会执行格式检查、测试和 `go vet`。
