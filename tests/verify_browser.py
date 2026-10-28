#!/usr/bin/env python3
"""真实 Chromium + 可控 Worker/时钟回归；只操作临时站点，不修改源码。
运行依赖：pip install playwright==1.64.1 && python -m playwright install --with-deps chromium
"""
import asyncio
import functools
import http.server
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import time

from playwright.async_api import async_playwright

from verify_network_timeout import run_network_timeout_checks

ROOT = Path(__file__).resolve().parents[1]
BASE_PASSWORD = 'WueNKY^SRHRh4!DL'
FAKE_PASSWORD = 'LatestResult1!Ab'
CHECKS = 0
MOCK_WORKER = """(() => {
    window.__workers = [];
    window.Worker = class {
        constructor() { this.messages = []; this.terminated = false; __workers.push(this); }
        postMessage(payload) { this.messages.push(payload); }
        terminate() { this.terminated = true; }
        reply(data) { if (this.onmessage) this.onmessage({data}); }
    };
})();"""
WASM_PROBE = """(() => {
    globalThis.__wasmCompiled = 0;
    if (typeof WebAssembly !== 'object') return;
    const Original = WebAssembly.Module;
    WebAssembly.Module = new Proxy(Original, {
        construct(target, args) {
            const module = Reflect.construct(target, args);
            globalThis.__wasmCompiled++;
            return module;
        }
    });
    // hash-wasm uses asynchronous instantiate(bytes), not the PoC's Module constructor.
    for (const name of ['compile', 'instantiate']) {
        const original = WebAssembly[name].bind(WebAssembly);
        WebAssembly[name] = (...args) => original(...args).then(result => {
            globalThis.__wasmCompiled++;
            return result;
        });
    }
})();"""


def check(condition, name):
    global CHECKS
    assert condition, name
    CHECKS += 1


async def poll(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await predicate():
            return
        await asyncio.sleep(0.05)
    raise AssertionError('timed out waiting for browser state')


async def ready(page):
    await poll(lambda: page.evaluate("!document.getElementById('copy-btn').disabled && document.getElementById('derive-bar').hidden"))


async def fill(page, master='correct horse battery staple', code='github'):
    await page.fill('#master-input', master)
    await page.fill('#code-input', code)


async def requests(page, index=-1):
    return await page.evaluate("index => __workers.at(index).messages.filter(m => m.type === 'derive')", index)


async def reply(page, payload, password=FAKE_PASSWORD, index=-1):
    await page.evaluate("args => __workers.at(args.index).reply({id: args.id, ok: true, password: args.password})",
                        {'index': index, 'id': payload['id'], 'password': password})


async def mock_page(browser, url):
    context = await browser.new_context(ignore_https_errors=True)
    page = await context.new_page()
    await page.clock.install()
    await page.add_init_script(MOCK_WORKER)
    await page.goto(url)
    await page.evaluate("document.getElementById('policy').open = true")
    return context, page


async def test_queue(browser, url):
    context, page = await mock_page(browser, url)
    try:
        await fill(page)
        await page.clock.run_for(300)
        first = (await requests(page))[0]
        await reply(page, first)
        check(await page.is_enabled('#copy-btn'), 'mock baseline available')
        await page.fill('#code-input', 'changed')
        check(not await page.is_enabled('#copy-btn'), 'edit invalidates copy before debounce')
        check(await page.inner_text('#strength-label') == '—', 'edit also invalidates strength')
        await page.clock.run_for(300)
        second = (await requests(page))[-1]
        await page.fill('#code-input', 'latest')
        await page.clock.run_for(300)
        check(len(await requests(page)) == 2, 'only one derive may be in the Worker')
        await page.evaluate('__workers.at(-1).reply({id: -1, ok: true, password: "bad"})')
        check(len(await requests(page)) == 2, 'unknown reply does not release the current task')
        await reply(page, second)
        third = (await requests(page))[-1]
        check(third['code'] == 'latest', 'pending request coalesces to latest input')
        await reply(page, second)
        await reply(page, third)
        check(await page.inner_text('#password-output') == FAKE_PASSWORD, 'duplicate old reply cannot discard current result')
        await page.fill('#code-input', 'malformed-result'); await page.clock.run_for(300)
        malformed=(await requests(page))[-1]
        await page.evaluate('id=>__workers[0].reply({id,ok:true,password:null})', malformed['id'])
        check(not await page.is_enabled('#copy-btn') and await page.is_hidden('#derive-bar'), 'malformed success is fail-closed without stuck spinner')
        await page.click('#mode-chips [data-mode=pin]')
        check(not await page.is_enabled('#copy-btn'), 'strategy change immediately invalidates output')
        await page.clock.run_for(300)
        pin = (await requests(page))[-1]
        check(pin['length'] == 6, 'PIN retains original six-digit default')
        await reply(page, pin, '845961')
        check('PIN' in await page.inner_text('#strength-label'), 'PIN never rated extreme')
        check(await page.eval_on_selector_all('#len-chips .chip', "els => els.every(e => e.disabled && e.getAttribute('aria-pressed') === 'false')"), 'PIN length chips disabled without false highlight')
        await page.click('#mode-chips [data-mode=full]')
        await page.clock.run_for(300)
        full = (await requests(page))[-1]
        check(full['length'] == 16, 'return from PIN restores full length')
        await reply(page, full)
        await page.fill('#counter-input', '2')
        check(not await page.is_enabled('#copy-btn'), 'counter input invalidates result before blur')
        await page.clock.run_for(300)
        counter = (await requests(page))[-1]
        check(counter['counter'] == 2, 'counter input is used without requiring change/blur')
        await reply(page, counter)
        await page.fill('#master-input', '')
        check(not await page.is_enabled('#copy-btn'), 'manual clear invalidates immediately')
        await page.clock.run_for(300)
        check(await page.inner_text('#password-output') == '请填写完整的主密码和代号', 'manual clear stays empty')
    finally:
        await context.close()
    print('PASS browser: queue, stale replies, PIN and input invalidation')


async def test_timeout_and_reset(browser, url):
    context, page = await mock_page(browser, url)
    try:
        await fill(page); await page.clock.run_for(300)
        first = (await requests(page))[0]
        await page.evaluate('() => { window.__lateHandler = __workers[0].onmessage; }')
        await page.fill('#code-input', 'newest'); await page.clock.run_for(300)
        await page.clock.run_for(60001)
        check(await page.evaluate('__workers[0].terminated'), 'watchdog terminates hung Worker')
        check(await page.evaluate('__workers.length') == 2, 'pending task gets a fresh Worker')
        latest = (await requests(page))[-1]
        check(latest['code'] == 'newest', 'watchdog retries only the latest pending task')
        await page.evaluate("id => __lateHandler({data: {id, ok:true, password:'OLD'}})", first['id'])
        await reply(page, latest)
        check(await page.inner_text('#password-output') == FAKE_PASSWORD, 'late old Worker cannot destroy new task')
        await page.fill('#code-input', 'will-timeout'); await page.clock.run_for(300)
        await page.clock.run_for(60001)
        check(await page.evaluate('__workers.at(-1).terminated'), 'latest timed-out Worker also terminates')
        check('超时' in await page.inner_text('#password-output'), 'timeout shown only for current task')
        check(await page.is_hidden('#derive-bar') and not await page.is_enabled('#copy-btn'), 'timeout cannot leave spinner or stale copy')
        await page.fill('#code-input', 'after-timeout'); await page.clock.run_for(300)
        check(await page.evaluate('__workers.length') == 3, 'next input recovers after timeout')
        await page.click('#reset-btn')
        check(await page.evaluate('__workers.at(-1).terminated'), 'reset cancels in-flight computation')
        await page.clock.run_for(60001)
        check(await page.inner_text('#password-output') == '请输入主密码和代号', 'reset cannot be overwritten by timeout')
        check(not await page.is_enabled('#copy-btn'), 'reset cannot re-enable copy')
        await fill(page); await page.click('#reset-btn'); await page.clock.run_for(300)
        check(await page.evaluate('__workers.length') == 3, 'reset also cancels debounce before dispatch')
    finally:
        await context.close()
    print('PASS browser: watchdog, replacement Worker and reset races')


async def test_local_fallback(browser, url):
    for failure in ['constructor', 'post', 'error', 'messageerror']:
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        await page.clock.install()
        await page.add_init_script(WASM_PROBE)
        script = MOCK_WORKER
        if failure == 'constructor':
            script = "window.Worker = class { constructor() { throw new Error('blocked'); } };"
        elif failure == 'post':
            script += "Worker.prototype.postMessage = function () { throw new Error('post failed'); };"
        await page.add_init_script(script)
        try:
            await page.goto(url); await fill(page); await page.clock.run_for(300)
            if failure in ['error', 'messageerror']:
                await page.evaluate("type => __workers[0]['on' + type]({preventDefault() {}})", failure)
                check(await page.evaluate('__workers[0].terminated'), failure + ' terminates failed Worker')
            await ready(page)
            check(await page.inner_text('#password-output') == BASE_PASSWORD, failure + ' fallback is bit-identical')
            check(await page.evaluate('__wasmCompiled') > 0, failure + ' fallback compiles WASM under CSP')
            check(await page.evaluate('spv2CoreFactory(null, false).provider()') == 'hash-wasm', failure + ' fallback passed cross-provider gate')
        finally:
            await context.close()
    # 实际拦截 Worker 脚本，验证浏览器的异步加载失败路径，而不只用模拟事件。
    context = await browser.new_context(ignore_https_errors=True, service_workers='block')
    page = await context.new_page()
    await page.add_init_script(WASM_PROBE)
    await context.route('**/assets/js/spv2-worker.js', lambda route: route.abort())
    try:
        await page.goto(url); await fill(page); await ready(page)
        check(await page.inner_text('#password-output') == BASE_PASSWORD, 'real blocked Worker recovers')
        check(await page.evaluate('__wasmCompiled') > 0, 'real blocked Worker uses local WASM')
    finally:
        await context.close()
    print('PASS browser: Worker constructor/post/load/message failures and CSP fallback')


async def test_async_local_queue(browser, url):
    # Deterministically resolve old Web Crypto promises after a replacement task.
    context = await browser.new_context(ignore_https_errors=True, service_workers='block')
    await context.route('**/assets/js/spv2-core.js', lambda route: route.fulfill(
        content_type='text/javascript', body="""
        window.__localCalls=[];window.__localWipes=0;
        window.spv2CoreFactory=()=>({
            derive(payload){return new Promise((resolve,reject)=>__localCalls.push({payload,resolve,reject}));},
            wipeSession(){__localWipes++;return Promise.resolve();}
        });"""))
    page = await context.new_page(); await page.clock.install()
    await page.add_init_script("window.Worker=class{constructor(){throw new Error('blocked')}}")
    async def count(): return await page.evaluate('__localCalls.length')
    async def resolve(index, password=FAKE_PASSWORD):
        await page.evaluate('args=>__localCalls[args.index].resolve({password:args.password})', {'index':index,'password':password})
    try:
        await page.goto(url); await fill(page); await page.clock.run_for(300)
        await page.fill('#code-input','second'); await page.clock.run_for(300)
        await page.fill('#code-input','third'); await page.clock.run_for(300)
        check(await count()==1,'async local path has only one active derive')
        await resolve(0)
        check(await count()==2 and await page.evaluate('__localCalls[1].payload.code')=='third','async pending slot keeps only newest input')
        await resolve(1)
        check(await page.inner_text('#password-output')==FAKE_PASSWORD,'async newest result displayed')
        await page.fill('#code-input','old-after-reset'); await page.clock.run_for(300)
        await page.click('#reset-btn'); await fill(page,code='after-reset'); await page.clock.run_for(300)
        check(await count()==4,'reset starts replacement local task')
        await resolve(2,'OLD')
        check(not await page.is_enabled('#copy-btn') and not await page.is_hidden('#derive-bar'),'old local completion cannot finish replacement task')
        await page.fill('#code-input','after-reset-final'); await page.clock.run_for(300)
        check(await count()==4,'old local completion cannot release busy slot')
        await resolve(3)
        check(await count()==5 and await page.evaluate('__localCalls[4].payload.code')=='after-reset-final','new local pending dispatches after its own task')
        await resolve(4,FAKE_PASSWORD)
        check(await page.inner_text('#password-output')==FAKE_PASSWORD,'no old local result resurrects after reset')
        await page.fill('#code-input','pagehide-inflight'); await page.clock.run_for(300)
        await page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide'));window.dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));")
        check(await count()==7,'BFCache restore starts fresh local request')
        await page.evaluate("__localCalls[5].reject(new Error('late old error'))")
        check(not await page.is_hidden('#derive-bar'),'late local rejection cannot finish BFCache replacement')
        await resolve(6)
        check(await page.is_enabled('#copy-btn'),'BFCache replacement completes normally')
    finally:
        await context.close()
    print('PASS browser: async Web Crypto queue, reset and BFCache races')


async def test_noble_fallback(browser, url):
    context=await browser.new_context(ignore_https_errors=True)
    page=await context.new_page()
    await page.add_init_script("window.Worker=class{constructor(){throw new Error('blocked')}};window.WebAssembly=undefined;")
    try:
        await page.goto(url);await fill(page);await ready(page)
        check(await page.inner_text('#password-output')==BASE_PASSWORD,'real noble fallback keeps baseline password')
        check(await page.evaluate('spv2CoreFactory(null,false).provider()')=='noble-hashes','actual WASM-disabled browser uses noble')
    finally:
        await context.close()
    print('PASS browser: real noble fallback with WASM unavailable')


async def test_copy_and_theme(browser, url):
    context, page = await mock_page(browser, url)
    try:
        await fill(page); await page.clock.run_for(300)
        await reply(page, (await requests(page))[-1])
        await page.evaluate("""() => {
            window.__copied = []; window.__reads = 0;
            Object.defineProperty(navigator, 'clipboard', {configurable:true, value: {
                writeText(text) { __copied.push(text); return new Promise(resolve => window.__resolveCopy = resolve); },
                readText() { __reads++; return Promise.resolve('other private text'); }
            }});
        }""")
        await page.click('#copy-btn')
        await page.fill('#code-input', 'changed-while-copying')
        await page.evaluate('__resolveCopy()')
        check(await page.inner_text('#copy-label') == '复制密码', 'old async copy cannot mark a newer result copied')
        check(await page.evaluate('__copied[0]') == FAKE_PASSWORD, 'copy captures the clicked result')
        await page.clock.run_for(45001)
        check(await page.evaluate('__reads') == 0, 'no unsolicited clipboard read or unreliable auto-wipe')
        await reply(page, (await requests(page))[-1])
        await page.evaluate("""() => {
            navigator.clipboard.writeText = () => Promise.reject(new Error('denied'));
            document.execCommand = () => true;
        }""")
        await page.focus('#code-input'); await page.press('#code-input', 'Enter')
        await poll(lambda: page.evaluate("document.getElementById('copy-label').textContent === '已复制'"))
        check(await page.evaluate('document.activeElement.id') == 'code-input', 'fallback copy restores keyboard focus')
        check(await page.locator('textarea').count() == 0, 'fallback copy removes temporary plaintext textarea')
        await page.emulate_media(color_scheme='dark')
        await page.evaluate("localStorage.setItem('sp-theme', 'light')")
        await page.reload()
        check(await page.get_attribute('html', 'data-theme') == 'light', 'stored light theme survives reload under dark OS')
    finally:
        await context.close()
    print('PASS browser: async clipboard feedback, focus and theme restore')


async def test_real_crypto(browser, url):
    context = await browser.new_context(ignore_https_errors=True)
    page = await context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.on('console', lambda msg: errors.append(msg.text) if msg.type in ('error', 'warning') else None)
    try:
        await page.goto(url)
        await poll(lambda: asyncio.sleep(0, result=bool(page.workers)))
        worker = page.workers[0]
        await worker.evaluate(WASM_PROBE)
        await fill(page); await ready(page)
        check(await page.inner_text('#password-output') == BASE_PASSWORD, 'real Worker baseline vector')
        check(await worker.evaluate('__wasmCompiled') > 0, 'real Worker actually compiles WASM')
        check(await worker.evaluate('spv2CoreFactory(null, false).provider()') == 'hash-wasm', 'real Worker passed provider gate')
        check(await page.get_attribute('#master-input', 'autocomplete') == 'off', 'production autocomplete policy unchanged')
        # 修改输入本身不应发起网络请求；初次加载/安装 PWA 的静态请求不算派生请求。
        await poll(lambda: page.evaluate('!!navigator.serviceWorker.controller'))
        network = []
        page.on('request', lambda request: network.append(request.url))
        await page.evaluate("document.getElementById('policy').open = true")
        await page.click('#mode-chips [data-mode=pin]'); await ready(page)
        check(await page.inner_text('#password-output') == '845961', 'real PIN remains original six digits')
        await page.click('#mode-chips [data-mode=full]'); await ready(page)
        await page.click('#len-chips [data-len="20"]'); await ready(page)
        check(await page.inner_text('#password-output') == 'vT_Hx%h9j@SwbpMQj&1D', 'full 20 baseline unchanged')
        await page.click('#mode-chips [data-mode=pin]'); await ready(page)
        await page.click('#mode-chips [data-mode=full]'); await ready(page)
        check(await page.inner_text('#password-output') == 'vT_Hx%h9j@SwbpMQj&1D', 'PIN switch retains selected full length')
        await page.click('#len-chips [data-len="16"]'); await ready(page)
        vector = next(v for v in json.loads((ROOT / 'tests/compat-vectors.json').read_text(encoding='utf-8'))['vectors'] if v['args'][1] == 'long-master-site')
        await fill(page, vector['args'][0], vector['args'][1]); await ready(page)
        check(await page.input_value('#master-input') == vector['args'][0], 'master longer than 512 UTF-16 units is not truncated')
        check(await page.inner_text('#password-output') == vector['pwd'], 'long master reproduces baseline output')
        check(network == [], 'typing and policy changes send no network requests')
        check(errors == [], 'real baseline has no console errors or warnings: ' + repr(errors))
    finally:
        await context.close()
    print('PASS browser: real WASM, baseline compatibility, long master and network privacy')


async def test_service_worker(browser, url, site, state):
    context = await browser.new_context(ignore_https_errors=True)
    page = await context.new_page()
    try:
        await page.goto(url)
        await poll(lambda: page.evaluate('!!navigator.serviceWorker.controller'))
        # 只改 HTML/core，故意不改 service-worker.js 与版本号。
        html_path = site / 'app/index.html'
        html_path.write_text(html_path.read_text(encoding='utf-8').replace('<html ', '<html data-review="new" ', 1), encoding='utf-8')
        core_path = site / 'app/assets/js/spv2-core.js'
        core_path.write_text(core_path.read_text(encoding='utf-8') + '\nglobalThis.__coreReviewMarker = "new";\n', encoding='utf-8')
        await page.reload()
        check(await page.get_attribute('html', 'data-review') == 'new', 'online shell updates without SW version bump')
        check(await page.evaluate('globalThis.__coreReviewMarker') == 'new', 'online core also updates without version bump')
        await context.set_offline(True)
        for suffix in ['?offline=1', 'index.html?offline=2']:
            await page.goto(url.rsplit('/', 1)[0] + '/' + suffix)
            check(await page.get_attribute('html', 'data-review') == 'new', 'offline alias uses newest runtime shell: ' + suffix)
            check(await page.evaluate('globalThis.__coreReviewMarker') == 'new', 'offline core uses newest runtime cache')
        await fill(page); await ready(page)
        check(await page.inner_text('#password-output') == BASE_PASSWORD, 'offline Worker derivation remains correct')
        await context.set_offline(False)
        state['server_error'] = True
        await page.reload()
        check(await page.get_attribute('html', 'data-review') == 'new', 'HTTP 503 falls back to usable offline shell')
        check(await page.evaluate('typeof spv2CoreFactory') == 'function', 'HTTP 503 still loads cached core')
    finally:
        state['server_error'] = False
        await context.close()
    print('PASS browser: HTTPS service-worker update, query aliases, offline derivation and HTTP 503')


async def test_malformed_results(browser, url):
    # Worker transport success is a strict boolean; output must match the
    # requested ASCII pool/length. These are fault injections, not assertions
    # that the real production engine normally produces malformed results.
    context, page = await mock_page(browser, url)
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    invalid = [
        {'ok': 'true', 'password': FAKE_PASSWORD}, {'ok': True},
        {'ok': True, 'password': None}, {'ok': True, 'password': 32},
        {'ok': True, 'password': ''}, {'ok': True, 'password': 'SHORT'},
        {'ok': True, 'password': '星' * 16}, {'ok': True, 'password': '|' * 16},
        {'ok': True, 'password': '0' * 17},
    ]
    try:
        for index, data in enumerate(invalid):
            await fill(page, code=f'bad-worker-result-{index}'); await page.clock.run_for(300)
            sent = await requests(page)
            check(len(sent) == index + 1, 'malformed Worker response never blocks the next request')
            await page.evaluate('data => __workers.at(-1).reply(data)', {'id': sent[-1]['id'], **data})
            check(not await page.is_enabled('#copy-btn') and await page.is_hidden('#derive-bar')
                  and '派生失败' in await page.inner_text('#password-output'), 'malformed Worker result fails closed')
        for mode, bad in [('alnum', '!' * 16), ('pin', 'ABCDEF')]:
            await page.click(f'#mode-chips [data-mode={mode}]'); await page.clock.run_for(300)
            await reply(page, (await requests(page))[-1], bad)
            check(not await page.is_enabled('#copy-btn') and await page.is_hidden('#derive-bar'), mode + ' rejects a wrong character pool')
        await fill(page, code='valid-after-malformed'); await page.clock.run_for(300)
        await reply(page, (await requests(page))[-1], '845961')
        check(await page.is_enabled('#copy-btn'), 'valid PIN recovers after malformed Worker replies')
        check(errors == [], 'malformed Worker results cause no uncaught page exception')
    finally:
        await context.close()

    # Local async API has no ok/id envelope; null, wrong types and even a
    # throwing password getter must all release exactly their own busy slot.
    context = await browser.new_context(ignore_https_errors=True, service_workers='block')
    await context.route('**/assets/js/spv2-core.js', lambda route: route.fulfill(
        content_type='text/javascript', body="""
        window.__localCalls=[];window.__syncFault=false;
        window.spv2CoreFactory=()=>({
            derive(payload){
                if(__syncFault)throw new Error('INJECTED_sync_derive');
                return new Promise((resolve,reject)=>__localCalls.push({payload,resolve,reject}));
            },wipeSession(){return Promise.resolve();}
        });"""))
    page = await context.new_page(); await page.clock.install()
    await page.add_init_script("window.Worker=class{constructor(){throw new Error('blocked')}}")
    errors = []; page.on('pageerror', lambda error: errors.append(str(error)))
    local_invalid = [None, False, 32, {}, {'password': False}, {'password': ''},
                     {'password': 'SHORT'}, {'password': '星' * 16}, {'password': '|' * 16}]
    try:
        await page.goto(url)
        for index, value in enumerate(local_invalid):
            await fill(page, code=f'bad-local-result-{index}'); await page.clock.run_for(300)
            check(await page.evaluate('__localCalls.length') == index + 1, 'malformed local result never blocks the next request')
            await page.evaluate('args => __localCalls[args.index].resolve(args.value)', {'index': index, 'value': value})
            check(not await page.is_enabled('#copy-btn') and await page.is_hidden('#derive-bar')
                  and '派生失败' in await page.inner_text('#password-output'), 'malformed local result fails closed and finishes')
        await fill(page, code='throwing-result-getter'); await page.clock.run_for(300)
        await page.evaluate("__localCalls.at(-1).resolve(Object.defineProperty({},'password',{get(){throw new Error('INJECTED_result_getter')}}))")
        check(not await page.is_enabled('#copy-btn') and await page.is_hidden('#derive-bar'), 'throwing result getter is caught and releases busy slot')
        await fill(page, code='rejected-local-result'); await page.clock.run_for(300)
        await page.evaluate("__localCalls.at(-1).reject(new Error('INJECTED_local_rejection'))")
        check(not await page.is_enabled('#copy-btn') and await page.is_hidden('#derive-bar'), 'current local rejection releases busy slot')
        await page.evaluate('window.__syncFault=true')
        await fill(page, code='sync-local-error'); await page.clock.run_for(300)
        check(not await page.is_enabled('#copy-btn') and await page.is_hidden('#derive-bar'), 'synchronous local error also releases busy slot')
        await page.evaluate('window.__syncFault=false')
        await fill(page, code='valid-after-local-error'); await page.clock.run_for(300)
        await page.evaluate('password => __localCalls.at(-1).resolve({password})', FAKE_PASSWORD)
        check(await page.is_enabled('#copy-btn') and await page.inner_text('#password-output') == FAKE_PASSWORD, 'valid local result recovers after malformed completions')
        check(errors == [], 'malformed local results cause no unhandled page exception')
    finally:
        await context.close()
    print('PASS browser: malformed Worker/local responses, strict success flag, output bounds and recovery')


async def test_service_worker_read_failure(browser, url):
    # Patch only the real SW's runtime-cache operations, not its installed
    # precache or network. Browser CacheStorage itself still serves precache.
    context = await browser.new_context(ignore_https_errors=True)
    page = await context.new_page()
    try:
        await page.goto(url); await poll(lambda: page.evaluate('!!navigator.serviceWorker.controller'))
        await page.wait_for_load_state('networkidle')
        service_worker = context.service_workers[-1]
        await service_worker.evaluate("""() => {
            const nativeMatch=caches.match.bind(caches), nativeOpen=caches.open.bind(caches);
            self.__runtimeReadFaults=0;self.__runtimeOpenFaults=0;
            caches.match=(request,options)=>{
                if(options && options.cacheName===RUNTIME){self.__runtimeReadFaults++;throw new Error('INJECTED_runtime_read');}
                return nativeMatch(request,options);
            };
            caches.open=name=>{
                if(name===RUNTIME){self.__runtimeOpenFaults++;throw new Error('INJECTED_runtime_open');}
                return nativeOpen(name);
            };
        }""")
        await context.set_offline(True)
        await page.goto(url + '?runtime-fault=1')
        check(await page.evaluate('typeof spv2CoreFactory') == 'function', 'real precache loads core when runtime storage fails')
        await fill(page); await ready(page)
        check(await page.inner_text('#password-output') == BASE_PASSWORD, 'runtime read failure preserves real offline derivation')
        check(await service_worker.evaluate('__runtimeReadFaults') > 0, 'browser fault injection actually exercised runtime reads')
        check(await service_worker.evaluate('__runtimeOpenFaults') == 0, 'browser fallback never needs to create/open runtime cache')
    finally:
        await context.close()
    print('PASS browser: real CacheStorage precache fallback during runtime read failure')


async def main():
    with tempfile.TemporaryDirectory(prefix='starrypass-browser-') as temporary:
        site = Path(temporary)
        app = site / 'app'; app.mkdir()
        for filename in ['index.html', 'service-worker.js', 'manifest.webmanifest', 'favicon.ico']:
            shutil.copy2(ROOT / filename, app / filename)
        shutil.copytree(ROOT / 'assets', app / 'assets')
        cert, key = site / 'cert.pem', site / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        state = {'server_error': False}

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def end_headers(self):
                self.send_header('Cache-Control', 'no-store')
                super().end_headers()

            def do_GET(self):
                try:
                    if state['server_error']:
                        self.send_error(503)
                    else:
                        super().do_GET()
                except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                    # Context shutdown/route abort intentionally cancels requests.
                    pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Handler, directory=site))
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(cert, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        url = f'https://127.0.0.1:{server.server_port}/app/index.html'
        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(args=['--ignore-certificate-errors'])
                try:
                    await test_queue(browser, url)
                    await test_timeout_and_reset(browser, url)
                    await test_local_fallback(browser, url)
                    await test_async_local_queue(browser, url)
                    await test_malformed_results(browser, url)
                    await test_noble_fallback(browser, url)
                    await test_copy_and_theme(browser, url)
                    await test_real_crypto(browser, url)
                    await test_service_worker(browser, url, site, state)
                    await test_service_worker_read_failure(browser, url)
                    await run_network_timeout_checks(browser, check)
                finally:
                    await browser.close()
        finally:
            server.shutdown(); server.server_close(); thread.join()
    print(f'PASS browser: {CHECKS} assertions')


if __name__ == '__main__':
    asyncio.run(main())
