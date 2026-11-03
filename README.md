# StarryPass 星愿令 v2.1 For Production

**Made with love ❤️**

> 派生规范与 v2 逐位兼容，密码学原语采用平台原生 Web Crypto、固定版本的 @noble/hashes 与 vendored hash-wasm。
> 经固定测试向量、双提供方交叉对照与发行包回归验证，在原版派生出的每一个密码均可在此逐字节一致复现。

### 简单方便防破解，不一样的密码管理工具

同一主密码 + 站点代号，本地确定性生成高熵密码。

![image](https://raw.githubusercontent.com/lingyicute/StarryPass/main/banner.jpg)

## 🤔 为什么有两个版本？

本项目是 StarryPass 确定性密码生成器的**生产级版本**。

原版 StarryPass v2 的核心（`spv2-core.js`）采用**手写密码学实现**：自写的 SHA-256 / HMAC / HKDF / BLAKE2b / Argon2id，外加手工汇编的 WASM 压缩核。它内置 RFC KAT 自检，输出正确性已通过完整验证；而在生产环境中，基础密码学原语更适合交由经过广泛审计的标准化实现承担。

在安全领域，有一条黄金法则是：绝不要自己手搓加密算法 (Never roll your own crypto)。之前为了好玩以及当作一种智力挑战，我纯手工编写了 Argon2id 实现。然而，在实际的安全实践中，我们必须依赖标准化的工具。本仓库就是这样的生产级别版本 —— 它将自定义的加密算法替换为经受过实战检验、值得信赖的标准实现（Web Crypto、hash-wasm 与 @noble/hashes），以提供稳健可靠的生产级安全性。

如果你对该算法的底层运行机制感兴趣，可以去看看我最初的[手写实现版本](https://github.com/lingyicute/StarryPassPoC)。但请注意，那个手写版本纯粹是为了概念验证（PoC）而开发的。任何涉及实际生产环境的部署与使用，请务必认准本仓库。

这个生产级版本的立场是：**规范一个字节不变，实现全部换血。**

| 组件 | v2（原版） | v2.1 生产级（本版本） |
| --- | --- | --- |
| SHA-256 | 手写实现 | **Web Crypto** `crypto.subtle.digest`（平台实现，随浏览器/Node 一起接受审计） |
| HMAC-SHA-256 | 手写实现 | **Web Crypto** `crypto.subtle.sign` |
| HKDF-SHA-256 (RFC 5869) | 手写实现 | **Web Crypto** `crypto.subtle.deriveBits`（原生 HKDF） |
| Argon2id v1.3 (RFC 9106) | 手写 JS + 手工汇编 WASM 双路径 | **vendored hash-wasm 4.12.0**（WASM 主路径）+ **@noble/hashes 2.4.0**（MIT，成熟广泛审计的纯 JS 回退实现） |
| BLAKE2b | 手写实现 | 不再需要（仅 Argon2 内部使用，由库负责） |
| 会话随机数 | `getRandomValues` + `Math.random` 回退 | 强制 `crypto.getRandomValues`，**移除弱回退** |
| 规范逻辑（NFC 规范化、盐构造、HKDF 流布局、无偏拒绝采样、会话缓存） | — | 严格保持 v2 规范字节布局与输入输出语义，并配备故障恢复、内存清理与并发竞态回归测试 |

**应用层不自行实现密码学原语。** `src/spv2-core.mjs` 的底层密码学运算全部由平台原生 Web Crypto、`crypto.getRandomValues` 以及双 Argon2id 提供方（vendored `hash-wasm` / `@noble/hashes`）完成；域分离、参数序列化、会话缓存与字符合成严格遵循 v2 规范实现，并通过完整的自动化回归测试覆盖。

## ✅ 兼容性验证

兼容性不靠声明，靠和原版实现对拍：

1. **测试向量** — `tests/vectors.json`（7 条，由原版核心生成）→ **全部逐位一致**；
2. **黄金测试集** — `tests/golden.json`（原有 44 条保持不变，覆盖 Unicode、counter/length 边界截断、未知 mode/tier 回退、模式边界、paranoid 档与空输入错误）→ **全部逐位一致**；
3. **构建产物级测试** — `tests/verify_bundle.mjs` 直接加载发行文件
   `assets/js/spv2-core.js` 重跑向量 + 会话缓存 → **通过**；
4. **运行时自检（沿用原版开机已知答案自检 KAT）** —
   RFC 9106 §5.3 Argon2id KAT（同时覆盖 secret 与 associated data）+ RFC 5869 TC1 HMAC KAT；不通过则拒绝派生；
5. **移植回归** — 13 条额外固定兼容向量、真正的 NFD/NFC 与 trim 检查；源码/发行包分别在 WASM 与 noble 路径下共 **194 项**比较；核心边界/清理 **300 项**、SW **66 项**，另有 Chromium 浏览器回归（断言数以 `npm run test:browser` 输出为准）。

```bash
npm ci
npm test             # 核心/强度/SW 回归 + 原向量 + 构建产物
npm run test:golden   # 再加原有 44 条黄金用例
npm run test:compat   # 194 项源码/发行包、WASM/noble 固定答案与归一化检查
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

纯 JS 路径相较于 WASM 的耗时差异源于运行时的执行模型不同。交互与调度层通过以下机制保障流畅体验：

- 派生优先在独立 **Worker** 线程中执行，避免阻塞主线程 UI；当环境不支持 Worker 时自动回退本地生产核心（noble 路径采用 `argon2idAsync`，按 30 ms 周期让出事件循环）；
- **单槽会话缓存**语义不变：主密码 / 代号 / 档位不变时，轮换号、长度、模式的任何改动都**不再触发 Argon2**；
- 输入防抖仍为 280 ms；输入变化立即使旧结果不可复制，Worker 与异步本地回退均只保留最新待办任务，重置后的旧完成回调不会覆盖新任务；Worker 超时后自动终止并在后续请求时重建。

### ⚡ WASM 快速路径（已启用：vendored hash-wasm + 启动交叉门控）

上表的 noble 数字是**纯 JS 回退路径**基准。生产核心默认启用 **vendored
hash-wasm（WASM，含 `ad` 关联数据支持补丁）**，构建来源与校验信息见 `vendor/hash-wasm/PROVENANCE.md`：

| 档位 | hash-wasm (WASM) | noble (纯 JS 回退) | 倍差 |
| --- | --- | --- | --- |
| standard (64 MiB, t=3) | ~210–285 ms | ~1016–1420 ms | ~5× |
| paranoid (256 MiB, t=4) | ~1109 ms | ~5210 ms | 4.7× |

安全门控（不是简单 feature-detect）：

- **每次会话启动自检**用两个提供方各算一遍 RFC 9106 §5.3 向量
  （含 secret + ad），**逐位一致才启用 WASM 路径**；任何异常或不一致
  均自动回退到已通过独立 KAT 校验的 noble 路径，并记录一条不含敏感输入的降级诊断——派生正确性不依赖单一代码库。
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
- **口令合成**：采用无偏拒绝采样；full 默认要求包含大小写字母、数字与符号，保留最多 128 次候选采样后衔接确定性兜底构造，与 v2 规范完全一致
- **实现**：Web Crypto + vendored hash-wasm（启动交叉门控）/ @noble/hashes 回退
- **零持久化存储**：主密码与会话密钥仅驻留内存，不写入任何持久化存储。受控的敏感字节缓冲在使用后与异常路径下均通过 `finally` 清零；reset/pagehide 立即终止 Worker 并清理会话状态

### 🛡️ 运行时安全与工程机制

本版本在浏览器运行时的技术边界内实施完整的安全控制：应用层持有的敏感字节缓冲（主密码字节、会话密钥、HKDF 完整 ArrayBuffer 与分块、盐值及消息体）均通过 `finally` 及时覆写清零；同时在核心与 UI 层保障以下工程不变量：

- **协议不变**：共享站点盐、tier 同时参与盐构造与 Argon2 成本参数配置，换档仍会换密码；NFC/trim、大小写敏感、字符池、counter/length 夹取与未知 mode/tier 默认回退均与原版严格一致。
- **强制 CSPRNG**：会话随机掩码强制使用 `crypto.getRandomValues`；缺失或异常时立即拒绝派生并失败关闭，不发布未初始化的 nonce，也不回退 `Math.random`。
- **会话缓存隔离**：主线程与 Worker 各自维护独立会话 nonce；清空操作返回 Promise 并立即作废在途任务，确保过期结果不会写入缓存或更新 UI。
- **异步边界与双重校验**：调用时立即快照六个派生字段，后续外部对象修改不影响已入队任务。严格校验 Argon2 输出为恰好 32 字节的合法二进制缓冲；UI 层同时校验返回口令的长度与字符集策略。
- **强度评估**：延续启发式主密码强度评分模型与交互位置，并结合实际输出长度与字符池空间的理论上界（`实际长度 × log2(字符池大小)`）进行封顶计算。
- **策略状态管理**：PIN 模式默认使用 6 位长度，且在切回 full/alnum 时自动恢复先前选定的口令长度；底层 API 同时保留对显式 6/8 位参数的兼容支持。
- **剪贴板与输入防护**：仅响应用户显式复制操作，不自动读取剪贴板；主密码输入框保持 `autocomplete="off"` 等隐私属性。
- **发布门禁**：CI 依次执行发行包漂移校验、固定向量对拍、双提供方交叉比对与 Chromium 浏览器回归测试，验证全部通过后自动部署 Pages。

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
