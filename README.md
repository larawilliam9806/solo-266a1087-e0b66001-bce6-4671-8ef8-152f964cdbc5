# 网关证书链覆盖检查（离线）

维护窗口前，值班员提交 PEM 格式的网关叶证书、下发用中间证书和各机群的可信根，
指定 UTC 检查区间，服务按机群回答：**窗口内哪些时段有哪几条证书链可用，哪里断档**。

只核对三件事：

1. **签名** —— 链上每一跳都用签发者的公钥验证；
2. **CA 标记** —— 中间证书和根必须带 `BasicConstraints CA=TRUE`；
3. **有效期** —— 链的可用区间 = 链上所有证书有效期的交集。

每条链必须**止于该机群自己指定的可信根**；同一机群可以用多条不同的链接续覆盖窗口。
覆盖计算用区间扫描（只在链的起止边界切分），**不逐秒试验**。

## 启动

```bash
docker compose up --build
# 服务监听 http://localhost:8000 ，文档见 /docs
```

本地开发：

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
pytest            # 运行测试
```

## 接口

### `POST /check`

```json
{
  "window": {"start": "2026-11-26T00:00:00Z", "end": "2026-12-26T00:00:00Z"},
  "leaf_certificates":         [{"name": "gw-new",   "pem": "-----BEGIN CERTIFICATE-----..."}],
  "intermediate_certificates": [{"name": "ica-east", "pem": "-----BEGIN CERTIFICATE-----..."}],
  "clusters": [
    {"name": "east", "trusted_roots": [{"name": "root-east", "pem": "-----BEGIN CERTIFICATE-----..."}]}
  ]
}
```

- 时间可带任意 ISO 8601 偏移，内部一律归一到 UTC；不带时区按 UTC 处理。
- `name` 为可选标签，会在结果中原样带回，便于值班记录。

### 响应（按机群）

```json
{
  "window": {"start": "...", "end": "..."},
  "clusters": [
    {
      "name": "east",
      "full_coverage": true,
      "chains": [
        {"id": "chain-1", "names": ["gw-old", "ica-east", "root-east"],
         "subjects": ["CN=gw-old", "CN=ica-east", "CN=root-east"],
         "fingerprints": ["<sha256>", "<sha256>", "<sha256>"],
         "valid_from": "...", "valid_until": "..."}
      ],
      "timeline": [
        {"start": "...", "end": "...", "chains": [{"id": "chain-1", "fingerprints": ["..."]}]},
        {"start": "...", "end": "...", "chains": []}
      ],
      "gaps": [{"start": "...", "end": "..."}]
    }
  ]
}
```

- `chains`：该机群在窗口内所有验证通过的链（指纹按 叶→…→根 排列）及其可用区间；
- `timeline`：把窗口切成若干段，每段给出当时可用的链；`chains` 为空即断档；
- `gaps`：所有断档时段的起止时间；为空则 `full_coverage = true`。

### 快速体验

```bash
python scripts/gen_sample.py /tmp/sample          # 生成演示 PKI 和请求体
curl -s http://localhost:8000/check \
  -H 'Content-Type: application/json' \
  --data @/tmp/sample/request.json | jq
```

演示里 `east` 机群由新旧两张叶证书接续覆盖整个窗口，`west` 机群因根不匹配整段断档。

## 项目结构

```
app/main.py      FastAPI 入口与请求组装
app/service.py   解析、签名/CA 校验、建链、区间扫描
app/models.py    请求/响应模型（UTC 归一化）
tests/           服务层 + API 测试
scripts/gen_sample.py  演示数据生成
```
