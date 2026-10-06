# nodepool

从公开 gist 聚合免费代理节点 → 测活 → 用 [IPPure](https://ippure.com/) 公开接口测纯净度 →
维护节点池 → 生成并发布 Clash/mihomo 订阅。一次运行跑完整条流水线。

## 快速开始

```bash
python update.py                 # 跑完整流程（采集 + 测试 + 生成 + 发布）
python update.py --no-publish    # 只生成本地文件 output/clash.yaml，不发布
python update.py --skip-collect  # 不采集新节点，只复测现有池
python update.py --pages 5       # 覆盖搜索页数
python update.py --max-candidates 400
```

首次运行会自动把 mihomo 内核下载到 `bin/mihomo.exe`。

## 配置 GitHub Token（发布订阅需要）

在项目根目录建一个 `.env` 文件，写入（**不要提交到 git，不要分享**）：

```
GITHUB_TOKEN=github_pat_xxx
```

Token 只需勾选 **gist** 权限（classic token 勾 `gist`，或 fine-grained token 授予
Gists 读写）。它同时用于：
- 读取 gist 内容（授权后额度 5000 次/小时，远高于未授权的 60 次）；
- 创建 / 更新存放订阅的 **secret gist**。

首次发布会自动创建一个 secret gist 并把它的 id 记到 `data/gist.json`，之后每次更新同一个
gist，**订阅链接固定不变**。

## 在客户端里用

生成的订阅是 mihomo 格式，适用于 **Clash Verge Rev / FlClash / Mihomo Party** 等
mihomo 内核客户端（旧版 Clash for Windows 不支持 vless）。

- 导入订阅链接后，务必在客户端打开 **“通过代理更新订阅”**，因为链接在
  `gist.githubusercontent.com` 上，国内直连通常失败。
- 代理组：`🔰 手动选择`（总入口）/ `♻️ 自动选择`（延迟最低）/ 以及按纯净度分的
  `极度纯净` `纯净` `中性` 三个 url-test 组。国内网站走直连。

## 纯净度分级（IPPure 系数，越低越纯净）

| 系数区间 | 名称 |
|---|---|
| 0–15 | 极度纯净 |
| 15–25 | 纯净 |
| 25–40 | 中性 |

默认只收录系数 ≤ 40 的节点，可在 `config.yaml` 的 `purity.max_score` 调整。

## 工作目录

```
update.py          入口
config.yaml        所有参数
.env               你的 GitHub token（自建，git 忽略）
bin/mihomo.exe     内核（自动下载）
data/pool.json     节点池（持久化，记录每个节点的测试与纯净度历史）
data/gist.json     已发布 gist 的 id
output/clash.yaml  订阅文件本地副本
```

## 注意

- 免费公开节点随时可能失效、被滥用、被限速，“纯净”也只是某一时刻的快照。要稳定可用，
  还是自建 VPS 最可靠。
- 节点主人能看到你经由它访问了哪些站点，**不要用免费节点登录重要账号或传输敏感信息**。
- IPPure 的 `my.ippure.com/v1/info` 接口仍处测试阶段，若其返回结构变动，纯净度一步会报错
  或缺失（脚本不会输出未经检测的节点）。
- 脚本对 gist 访问做了节流；大幅调高 `search.pages` 或调低 `page_delay` 可能触发
  GitHub 限流。
