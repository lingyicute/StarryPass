# Service Worker 网络传输截止

本次在生产 `502e58f` 上移植 PoC `f96a303` 的运行时机制及 `3b0a97e` 的测试修正，不复制 PoC 整份 SW。

- 截止时间保持 **3000 ms**，覆盖等待响应头，以及导航/白名单静态资源的非 opaque 200 响应完整正文；不是“连续无新字节”的空闲超时。
- 通过读取 Response 副本检测正文完成，仍返回原 Response，保留 URL、类型、状态和头部。
- 通过 Promise.race 限制网络阶段，即使底层不响应 abort 也可以进入原有回退链；finally 清除定时器。超时后晚到结果不写入运行时缓存。
- 保留生产版按 cacheName 独立尽力读取、存储错误回退、路径命名空间、资源白名单与 waitUntil 写入链。404/503 的既有策略不改。
- 此策略可能中止正常但超过 3 秒的慢连接：有缓存时使用已有副本，无可用缓存时返回网络错误。超时传输不继续后台刷新缓存。本次没有擅改为其他秒数或双层等待策略。
- 全文预读增加缓冲并取消这些响应的流式交付。不为非白名单资源正文、缓存自身读写或安装时的 caches.addAll 设置截止时间；不能承诺所有页面操作严格在 3 秒内完成。

## 回归

`node tests/verify_sw.cjs` 合并原生产的存储/隔离检查与 PoC 可控时钟案例，共 63 项；夹具明确提供 AbortController 和计时器，覆盖响应头挂起、正文挂起、忽略 abort、无缓存、晚到响应、定时器清理与正常缓存更新。

`python3 tests/verify_browser.py` 同时运行 `verify_network_timeout.py`：真实 HTTPS、Service Worker、CacheStorage 与受控小资源，覆盖响应头停发、核心正文停发、HTML 导航正文停发和无缓存慢响应，另验证正常 Response 元数据与晚到响应不污染缓存。使用真实 SW 时钟，不将页面虚拟时钟误当作 SW 时钟。传输夹具不替代真实密码学/兼容性检查；原四路固定答案及完整发布门禁仍需通过。

上述网络修复只涉及 SW 传输及测试，不改变派生规范、KDF 成本、评分模型或 UI 布局。

## 关联的移动端点击高亮调整

另行移植 PoC `8f399621636e327b65335a5d5c70026111b3af36`：仅在 `html` 添加继承的 `-webkit-tap-highlight-color: transparent`，将原来按钮已有的浏览器原生高亮抑制覆盖到输入框、summary 等元素。既有自定义 ripple、`:active`、3px `:focus-visible`、UI 布局、内嵌字体和 autocomplete 不变。

浏览器回归增加 10 项，检查移动触屏模拟下继承后的透明值、真实 tap 的功能及自定义波纹、输入聚焦，以及真实 Tab 导航的可见焦点和按下态。只实测 Chromium 触屏模拟，不冒充 Safari/iPhone 真机覆盖。
