# StarryPass 星愿令 v2.1 For Production

**Made with love ❤️**

> 派生规范保持 v2 兼容，密码学原语使用 Web Crypto、固定版本的 @noble/hashes 与 vendored hash-wasm。
> 兼容性由固定答案、双提供方和发行包回归验证；使用标准库不代表整个应用已获得安全认证。

### 简单方便防破解，不一样的密码管理工具

同一主密码 + 站点代号，本地确定性生成高熵密码。

![image](https://raw.githubusercontent.com/lingyicute/StarryPass/main/banner.jpg)

## 🤔 为什么有两个版本？

本项目是 StarryPass 确定性密码生成器的**生产级版本**。

原版 StarryPass v2 的核心（`spv2-core.js`）是我**手搓的密码学**：自写的 SHA-256 / HMAC / HKDF / BLAKE2b / Argon2id，外加手工汇编的 WASM 压缩核。它带 RFC KAT 自检，正确性经受住了考验——但一份密码学代码只有我一个人看过，这本身就是风险。

在安全领域，有一条黄金法则是：绝不要自己手搓加密算法 (Never roll your own crypto)。之前为了好玩以及当作一种智力挑战，我纯手工编写了 Argon2id 实现。然而，在实际的安全实践中，我们必须依赖标准化的工具。本仓库就是这样的生产级别版本 —— 它将自定义的加密算法替换为经受过实战检验，值得信赖的库（@noble/hashes），以减少自写密码学原语的风险；应用集成、状态管理和依赖分支仍需要单独审查。

如果你对该算法的底层运行机制感兴趣，可以去看看我最初的[手写实现版本](https://github.com/lingyicute/StarryPassPoC)。但请注意，那个手写版本纯粹是为了概念验证（PoC）而开发的。任何涉及实际生产环境的部署与使用，请务必认准本仓库。

这个生产级版本的立场是：**规范一个字节不变，实现全部换血。**

| 组件 | v2（原版） | v2.1 生产级（本版本） |
| --- | --- | --- |
| SHA-256 | 手写实现 | **Web Crypto** `crypto.subtle.digest`（平台实现，随浏览器/Node 一起接受审计） |
| HMAC-SHA-256 | 手写实现 | **Web Crypto** `crypto.subtle.sign` |
| HKDF-SHA-256 (RFC 5869) | 手写实现 | **Web Crypto** `crypto.subtle.deriveBits`（原生 HKDF） |
| Argon2id v1.3 (RFC 9106) | 手写 JS + 手工汇编 WASM 双路径 | **@noble/hashes 2.4.0**（MIT，固定版本的纯 JS 回退提供方） |
| BLAKE2b | 手写实现 | 不再需要（仅 Argon2 内部使用，由库负责） |
| 会话随机数 | `getRandomValues` + `Math.random` 回退 | 强制 `crypto.getRandomValues`，**移除弱回退** |
| 规范逻辑（NFC 规范化、盐构造、HKDF 流布局、无偏拒绝采样、会话缓存） | — | 保持 v2 的规范字节与合法输入输出；集成层另有故障、清理与竞态回归 |

**应用不另写密码学原语。** `src/spv2-core.mjs` 调用 Web Crypto、`crypto.getRandomValues` 和两个 Argon2id 提供方（vendored hash-wasm / @noble/hashes）。域分离、序列化、缓存与字符合成仍是本项目的集成逻辑，需要自行测试。

## ✅ 兼容性验证

兼容性不靠声明，靠和原版实现对拍：

1. **测试向量** — `tests/vectors.json`（7 条，由原版手搓核心生成）→ **全部逐位一致**；
2. **黄金测试集** — `tests/golden.json`（原有 44 条保持不变，覆盖 Unicode、counter/length 边界截断、未知 mode/tier 回退、模式边界、paranoid 档与空输入错误）→ **全部逐位一致**；
3. **构建产物级测试** — `tests/verify_bundle.mjs` 直接加载发行文件
   `assets/js/spv2-core.js` 重跑向量 + 会话缓存 → **通过**；
4. **运行时自检（沿用原版 FIPS 风格开机自检）** —
   RFC 9106 §5.3 Argon2id KAT（同时覆盖 secret 与 associated data）+ RFC 5869 TC1 HMAC KAT；不通过则拒绝派生。这里的“FIPS 风格”只描述启动已知答案检查，不表示 FIPS 认证。
5. **移植回归** — 13 条额外固定兼容向量、真正的 NFD/NFC 与 trim 检查；源码/发行包分别在 WASM 与 noble 路径下共 **170 项**比较；核心故障/清理 **85 项**、SW **35 项**、Chromium **84 个断言**。详见 [核查与边界](docs/ported-hardening.md)。

```bash
npm ci
npm test             # 核心/强度/SW 回归 + 原向量 + 构建产物
npm run test:golden   # 再加原有 44 条黄金用例
npm run test:compat   # 170 项源码/发行包、WASM/noble 固定答案与归一化检查
npm run test:parity   # vendored Argon2id 与 noble 的生产参数交叉对照
# 浏览器测试需另装 playwright==1.64.1 与 Chromium：
python3 -m pip install playwright==1.64.1
python3 -m playwright install --with-deps chromium
npm run test:browser
```

`tests/generate_golden.mjs` 记录了黄金集的生成方式，以便日后复核出处。

## ⚡ 性能（数字随硬件浮动）

| 场景 | 原版（手搓 WASM） | v2.1 生产级（@noble/hashes） |
| --- | --- | --- |
| standard 档（64 MiB, t=3, p=4） | ~294 ms | ~1.3 s |
| paranoid 档（256 MiB, t=4, p=4） | ~1.2 s | ~6.7 s |
| 命中会话缓存（改轮换号/长度/模式） | ~1 ms | ~1 ms |

纯 JS 实现比手搓 WASM 慢是**用审计换算力**的诚实代价。缓解措施与原版一致且更进一步：

- 派生优先在 **Worker** 中执行；失败时回退本地生产核心。noble 本地路径用 `argon2idAsync`，按 30 ms 周期让步；本地 WASM 调用本身可能阻塞主线程，不能承诺全程保持动画；
- **单槽会话缓存**语义不变：主密码 / 代号 / 档位不变时，轮换号、长度、模式的任何改动都**不再触发 Argon2**；
- 输入防抖仍为 280 ms；输入变化立即使旧结果不可复制，Worker/异步本地回退都只保留最新待办，重置后的旧完成回调不能释放新任务。Worker 超时会终止并在后续请求重建。

### ⚡ WASM 快速路径（已启用：vendored hash-wasm + 启动交叉门控）

上表的 noble 数字是**回退路径**。生产核心现在默认走 **vendored
hash-wasm（WASM，含 `ad` 补丁分支）**，见 `vendor/hash-wasm/PROVENANCE.md`
（上游 PR 已提交待审，作者沉寂故先 vendor）：

| 档位 | hash-wasm (WASM) | noble (纯 JS 回退) | 倍差 |
| --- | --- | --- | --- |
| standard (64 MiB, t=3) | ~210–285 ms | ~1016–1420 ms | ~5× |
| paranoid (256 MiB, t=4) | ~1109 ms | ~5210 ms | 4.7× |

安全门控（不是简单 feature-detect）：

- **每次会话启动自检**用两个提供方各算一遍 RFC 9106 §5.3 向量
  （含 secret + ad），**逐位一致才启用 WASM 路径**；任何异常/不一致
  回退到 noble，并记录一条不含输入内容的降级诊断；noble 的自身 KAT 仍必须通过。启动交叉检查是防回归门控，不是完整正确性证明。
- `npm run test:parity` 离线再验 4 组生产参数逐位一致 + 基准；
- `provider()` 诊断接口存在，bundle 测试断言其为 `hash-wasm`，
  防止 CI 中静默退化。
- 端到端效果：黄金集测试 27.9 s → 8.1 s。

## 📁 目录结构

```
index.html              # 主页面
service-worker.js       # 缓存控制
assets/js/spv2-core.js  # 发行产物：esbuild 打包的生产核心（含 @noble/hashes）
assets/js/spv2-worker.js# importScripts 装载核心（与原版一致）
src/spv2-core.mjs       # 核心源码（可读版，构建入口）
vendor/hash-wasm/       # vendored hash-wasm@4.12.0 + ad 补丁构建（PROVENANCE.md）
tests/                  # 向量、黄金集、验证脚本与跨库一致性测试
scripts/subset_font.py  # 字体子集化脚本
THIRD_PARTY_NOTICES.md  # @noble/hashes + hash-wasm (均 MIT) 许可证
```

建议 Node 24；依赖要求 Node >=20.19.0。

构建：`npm run build`（esbuild，产物已入库；CI 会重构建并 `git diff` 校验漂移，防止改了源码忘发布产物）。

## 🔐 密码学（派生规范 —— 与 v2 完全一致）

- **KDF**：Argon2id v1.3（RFC 9106）
  - 标准档：64 MiB / t=3 / p=4
  - 极高档：256 MiB / t=4 / p=4
- **域分离盐**：`SHA-256("StarryPass-v2:salt\0" ‖ LE32(codeBytes.length) ‖ codeBytes ‖ tier_id)`，其中 `codeBytes = UTF8(NFC(trim(code)))`，tier_id 为一字节；代号区分大小写
- **展开**：HKDF-SHA-256（RFC 5869）绑定轮换序号、长度、字符集与代号
- **口令合成**：字符抽样采用拒绝采样；full 默认要求大小写、数字、符号。保留最多 128 次候选重试及原有兜底，不声称兜底后的全分布严格均匀
- **实现**：Web Crypto + vendored hash-wasm（启动交叉门控）/ @noble/hashes 回退
- **无应用持久化口令存储**：不把主密码/会话密钥写入应用存储。受控的敏感字节缓冲尽力在使用后与异常路径清零；reset/pagehide 终止 Worker，本地异步回退在当前操作结束后完成排队清理。不能保证离开页面时所有副本立即擦除

### 诚实的安全边界（相对原版的一处如实差异）

即使自写实现，也不能保证浏览器/GC/系统中的全部副本安全擦除。本版本用 `finally` 清理自己持有的敏感字节缓冲，HKDF 原生返回的完整 ArrayBuffer 与被替换的块也清理；但 JS 字符串、DOM、Web Crypto 的 CryptoKey、第三方库内部和系统剪贴板历史不在可验证的完全擦除范围内。WASM/浏览器保留容量也不等于敏感内容必然残留。

- **协议不变**：共享站点盐、tier 同时影响盐与 Argon2 成本，换档仍会换密码；NFC/trim、大小写敏感、字符池、counter/length 夹取与未知 mode/tier 普通回退均保留。
- **CSPRNG 仍为必需**：缺失/抛错时持续拒绝派生，绝不发布失败时的全零/半填充 nonce，也不增加 Math.random 回退。
- **缓存**：每个引擎独立 nonce；清空返回 Promise，并立即作废此前任务。无法强行中断正在执行的原生调用，但其结果不能发布到缓存或 UI。
- **异步边界**：调用时快照六个派生字段；请求对象后续改动不影响已排队任务。Argon2 输出须是恰好 32 字节的合法二进制类型，否则拒绝并清理；UI 同时拒绝长度/字符池不符的后端结果。
- **评分不是熵证明**：仍使用原启发式模型、原位置/文案；新增实际输出长度与字符池空间的理论上界，不等于实际猜测次数或破解时间。
- **已有错误 UI 路径**：旧版可能意外生成 6 位 full 或 8 位 PIN。现在默认 PIN 仍为 6 位且不覆盖 full/alnum 的所选长度；底层 API 保留合法 6/8 位参数，可按当时实际参数复现，修复不继续复刻错误状态。
- **剪贴板**：仅响应显式复制，不自动读取，也不承诺定时擦除；主密码原有 `autocomplete="off"` 保留，但浏览器/密码管理器不一定遵循提示。
- **发布门禁**：CI 先检查发行包漂移、固定答案、双提供方和浏览器回归，Pages 等待同一提交验证通过；这不等于已获得独立生产安全认证，也未证明跨标签页部署的原子性。

完整逐项判定、未移植项目和验证边界见 [docs/ported-hardening.md](docs/ported-hardening.md)。

## 🗂️ License

StarryPass is released under the GNU Affero General Public License v3.0 (AGPLv3).

Copyright (C) 2024-2026 lingyicute.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see https://www.gnu.org/licenses.

## 🗂️ Third Party License

`@noble/hashes` 与 `hash-wasm`（vendored 构建）均为 MIT 许可证，
全文见 `THIRD_PARTY_NOTICES.md` 与 `vendor/hash-wasm/LICENSE`。
