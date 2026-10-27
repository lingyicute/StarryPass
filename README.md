# StarryPass 星愿令 v2.1 For Production

**Made with love ❤️**

> 派生规范与 v2 逐位兼容；但密码学原语 100% 替换为成熟、被广泛审计的实现。
> 在原版派生出的每一个密码，在这里都一个字节不差地复现。

### 简单方便防破解，不一样的密码管理工具

同一主密码 + 站点代号，本地确定性生成高熵密码。

![image](https://raw.githubusercontent.com/lingyicute/StarryPass/main/banner.jpg)

## 🤔 为什么有两个版本？

本项目是 StarryPass 确定性密码生成器的**生产级版本**。

原版 StarryPass v2 的核心（`spv2-core.js`）是我**手搓的密码学**：自写的 SHA-256 / HMAC / HKDF / BLAKE2b / Argon2id，外加手工汇编的 WASM 压缩核。它带 RFC KAT 自检，正确性经受住了考验——但一份密码学代码只有我一个人看过，这本身就是风险。

在安全领域，有一条黄金法则是：绝不要自己手搓加密算法 (Never roll your own crypto)。之前为了好玩以及当作一种智力挑战，我纯手工编写了 Argon2id 实现。然而，在实际的安全实践中，我们必须依赖标准化的工具。本仓库就是这样的生产级别版本 —— 它将自定义的加密算法替换为经受过实战检验，值得信赖的库（@noble/hashes），以确保最高级别的安全性。

如果你对该算法的底层运行机制感兴趣，可以去看看我最初的[手写实现版本](https://github.com/lingyicute/StarryPassPoC)。但请注意，那个手写版本纯粹是为了概念验证（PoC）而开发的。任何涉及实际生产环境的部署与使用，请务必认准本仓库。

这个生产级版本的立场是：**规范一个字节不变，实现全部换血。**

| 组件 | v2（原版） | v2.1 生产级（本版本） |
| --- | --- | --- |
| SHA-256 | 手写实现 | **Web Crypto** `crypto.subtle.digest`（平台实现，随浏览器/Node 一起接受审计） |
| HMAC-SHA-256 | 手写实现 | **Web Crypto** `crypto.subtle.sign` |
| HKDF-SHA-256 (RFC 5869) | 手写实现 | **Web Crypto** `crypto.subtle.deriveBits`（原生 HKDF） |
| Argon2id v1.3 (RFC 9106) | 手写 JS + 手工汇编 WASM 双路径 | **@noble/hashes 2.4.0**（MIT、npm 周下载千万级、被大量安全项目采用的纯 JS 实现） |
| BLAKE2b | 手写实现 | 不再需要（仅 Argon2 内部使用，由库负责） |
| 会话随机数 | `getRandomValues` + `Math.random` 回退 | 强制 `crypto.getRandomValues`，**移除弱回退** |
| 规范逻辑（NFC 规范化、盐构造、HKDF 流布局、无偏拒绝采样、会话缓存） | — | 按 v2 规范逐行移植（这部分是*规格*，不是密码学原语） |

**没有一行密码学原语是自己写的。** 本版本源码中 `src/spv2-core.mjs` 的全部加密操作只由三类调用构成：`crypto.subtle.*`、`crypto.getRandomValues`、`@noble/hashes` 的 `argon2id`。

## ✅ 兼容性验证

兼容性不靠声明，靠和原版实现对拍：

1. **测试向量** — `tests/vectors.json`（7 条，由原版手搓核心生成）→ **全部逐位一致**；
2. **黄金测试集** — `tests/golden.json`（44 条，由原版核心生成，覆盖 NFC/NFD 归一化、emoji/CJK/全角、counter/length 边界截断、未知 mode/tier 回退、三种模式边界、paranoid 档、空输入错误路径）→ **全部逐位一致**；
3. **构建产物级测试** — `tests/verify_bundle.mjs` 直接加载发行文件
   `assets/js/spv2-core.js` 重跑向量 + 会话缓存 → **通过**；
4. **运行时自检（沿用原版 FIPS 风格开机自检）** —
   RFC 9106 §5.3 Argon2id KAT（同时覆盖 secret 与 associated data）+ RFC 5869 TC1 HMAC KAT；不通过则拒绝派生。

```bash
npm ci
npm test           # 向量 + 构建产物测试（快）
npm run test:golden # 再加 44 条黄金用例（完整，约 1 分钟）
```

`tests/generate_golden.mjs` 记录了黄金集的生成方式，以便日后复核出处。

## ⚡ 性能（数字随硬件浮动）

| 场景 | 原版（手搓 WASM） | v2.1 生产级（@noble/hashes） |
| --- | --- | --- |
| standard 档（64 MiB, t=3, p=4） | ~294 ms | ~1.3 s |
| paranoid 档（256 MiB, t=4, p=4） | ~1.2 s | ~6.7 s |
| 命中会话缓存（改轮换号/长度/模式） | ~1 ms | ~1 ms |

纯 JS 实现比手搓 WASM 慢是**用审计换算力**的诚实代价。缓解措施与原版一致且更进一步：

- 派生始终在 **Worker** 中执行（本地回退路径用 `argon2idAsync`，按 30 ms 让出事件循环，进度条保持动画）；
- **单槽会话缓存**语义不变：主密码 / 代号 / 档位不变时，轮换号、长度、模式的任何改动都**不再触发 Argon2**；
- 输入防抖 280 ms 与乱序应答丢弃逻辑不变。

## 📁 目录结构

```
index.html              # 主页面
service-worker.js       # 缓存控制
assets/js/spv2-core.js  # 发行产物：esbuild 打包的生产核心（含 @noble/hashes）
assets/js/spv2-worker.js# importScripts 装载核心（与原版一致）
src/spv2-core.mjs       # 核心源码（可读版，构建入口）
tests/                  # 向量、黄金集、三套验证脚本
scripts/subset_font.py  # 字体子集化脚本
THIRD_PARTY_NOTICES.md  # @noble/hashes (MIT) 许可证
```

构建：`npm run build`（esbuild，产物已入库；CI 会重构建并 `git diff` 校验漂移，防止改了源码忘发布产物）。

## 🔐 密码学（派生规范 —— 与 v2 完全一致）

- **KDF**：Argon2id v1.3（RFC 9106）
  - 标准档：64 MiB / t=3 / p=4
  - 极高档：256 MiB / t=4 / p=4
- **域分离盐**：`SHA-256("StarryPass-v2:salt" ‖ len(code) ‖ NFC(code) ‖ tier_id)`
- **展开**：HKDF-SHA-256（RFC 5869）绑定轮换序号、长度、字符集与代号
- **口令合成**：无偏拒绝采样；默认保证大小写 + 数字 + 符号各至少一枚
- **实现**：本版本 = Web Crypto + @noble/hashes（详见上方替换表）
- **零存储**：主密码与会话密钥仅驻留内存，离开页面即清零

### 诚实的安全边界（相对原版的一处如实差异）

原版因全代码自持，可以声称"连库内部的临时副本都能亲手清零"。基于成熟库的实现**无法触及库与平台内部的临时缓冲*（@noble/hashes 的中间数组、WebCrypto 密钥句柄由平台管理）。本版本清零所有*自己持有*的缓冲（主密码字节、会话密钥、HKDF 块、盐、消息），这是业界所有基于标准库的密码学软件共同的边界 —— 用"少一层可控性"换"多一层被审计"。

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

`@noble/hashes` 为 MIT 许可证，全文见 `THIRD_PARTY_NOTICES.md`。
