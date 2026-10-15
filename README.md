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
| `internal/fingerprint` | Banner 归一化、HTTP/TLS 结构提取与规则匹配 |
| `internal/model` | 输入输出结构 |
| `rules/rules.json` | 识别规则 |
| `testdata/input.json` | 20 条自测数据，不是 Client 的硬编码输入 |
| `testdata/expected.json` | 这 20 条的预期结果，供端到端脚本核对 |
| `scripts/check_results.py` | 核对 Client 输出的字段、顺序和预期值 |

## 规则

规则按文件中的优先级竞争，数值大的优先。端口只在优先级相同的时候打破平局，服务跑在非默认端口也会匹配。产品规则高于只判断协议的规则。

字段：

- `name`：唯一名称
- `priority`：越大越优先
- `source`：规则能看到的证据。省略时等同于 `banner`
- `pattern`：Go 正则，可用 `(?P<name>...)` 命名捕获。它只作用在 `source` 选出的文本上
- `ports`：可选端口提示，不是硬条件
- `protocol`、`product`：命中后写入结果；`product` 可为空
- `version_group`、`os_hint_group`：对应捕获组，省略表示该字段留空
- `confidence`：0 到 1。配置超出范围、正则无法编译、捕获组不存在或 `source` 非法时，进程启动失败

`source` 目前有四种：

- `banner`：归一化后的整段 Banner。SSH、MySQL、Redis、FTP 使用这个来源，并且模式从 Banner 开头匹配。
- `http_server`：只有合法 HTTP/1.x 响应里的 `Server` 头值。nginx、Apache、Jetty、Microsoft-IIS 使用这个来源，正文里的同名字符串不会命中。
- `http_status`：同一条响应的状态行。没有可信产品时只返回 `HTTP`，产品和版本为空，置信度低于产品规则。
- `tls`：记录头、长度和握手类型一致时，引擎才提供固定文本 `TLS`。端口不能代替这个检查。

HTTP 状态行必须出现在 Banner 开头，状态码要在 100 到 599。只读取第一个空行之前的头。没有 `Server` 头时协议仍可以是 `HTTP`。重复的 `Server` 值相同则保留；值冲突则忽略产品，不从中挑一个。

MySQL 二进制规则要求 4 字节包头、协议字节 `0x0a`、版本和 NUL 结尾。文本规则只接受开头的 `MySQL version 8.0.32` 这种写法，不会把句子中间的版本号当成握手。Redis 只接受开头的 `+PONG`、`-NOAUTH`、`-ERR` 或 `-WRONGPASS`，版本留空。FTP 产品要出现在 `220` 欢迎语的起始结构里；只有明确写出 FTP 或 FileZilla 的通用欢迎语才用低置信度标成 FTP。SMTP 的 `220 ... ESMTP` 会保持 unknown。

增加一条规则只需要编辑 `rules/rules.json`。例如给合法响应的 `Server: Widget/4` 增加 `source` 为 `http_server` 的规则，重启 Server 后即可生效，不用改匹配循环。精度回归在：

```bash
go test ./internal/fingerprint -run 'Precision|CustomRule|InvalidSource|ParseHTTP'
```

自测数据覆盖 OpenSSH、nginx、Apache、Jetty、Microsoft-IIS、MySQL 5.7/8.0、Redis（`+PONG`、`-NOAUTH`、`-ERR`）、ProFTPD、vsFTPd、Pure-FTPd、TLS 记录前缀，以及不能当作 FTP 的 `QUIT`。

限制：这不是完整的服务探测库。未列入规则的软件不会被猜成相近产品。Redis 和 Pure-FTPd 这类没有版本证据的结果不会填版本。TLS 判断只覆盖带一致长度字段的握手记录前缀。

## Docker Compose

构建并启动 Server：

```bash
docker compose up --build -d
```

Server 在容器内监听 `8080`，宿主机只绑定 `127.0.0.1:8080`。健康检查由镜像里的 `/server health` 发起真实 HTTP 请求，不依赖 shell 或 curl。Client 使用 profile，不会在普通 `up` 时自动跑完退出。

```bash
curl http://127.0.0.1:8080/health
docker compose --profile client run --rm client > client-out.json
python scripts/check_results.py testdata/input.json testdata/expected.json client-out.json
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
go test -race ./...
go vet ./...
docker compose config --quiet
```

推送到 `main` 或打开 pull request 后，GitHub Actions 会执行格式检查、测试、竞态检测、`go vet`，并实际构建镜像、等待健康检查、运行 Client，再用 `scripts/check_results.py` 核对全部 20 条结果。
