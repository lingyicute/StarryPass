/* Immutable answers, not two providers merely agreeing with each other.
 * The existing 44-case production golden set remains unchanged (including its
 * documented mode/tier fallbacks). Additional vectors come from the audited
 * original PoC, including PIN6, NFD and a >512 UTF-16-unit master password.
 */
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { spv2CoreFactory } from '../src/spv2-core.mjs';
import { loadCore } from './helpers/load-core.mjs';

const read = file => JSON.parse(fs.readFileSync(new URL(file, import.meta.url), 'utf8'));
const golden = read('./golden.json').cases;
const original = read('./vectors.json');
const additional = read('./compat-vectors.json').vectors;
const bundle = fs.readFileSync(new URL('../assets/js/spv2-core.js',import.meta.url),'utf8');
const quiet = {warn() {}};
const bundleFactory = wasm => new Function('self','WebAssembly','console',bundle+';return self.spv2CoreFactory;')({},wasm?WebAssembly:undefined,quiet);
const asRequest = v => {
    const [master,code,tier,counter,length,mode]=v.args;
    return {master,code,tier,counter,length,mode};
};
const fixedCases = additional.map(v=>({args:asRequest(v),pwd:v.pwd}));
// Fixed answers from PoC 24f876a. 328 CJK characters plus 40 framing
// bytes land exactly on the native limit; one extra ASCII byte exceeds it.
const longCode = '址'.repeat(328);
const longCodeCases = [
    [longCode, 1, 16, 'oHmWTR*9Q1&h*Jus'],
    [longCode + 's', 1, 16, '0%WfbfO-V1Lu=snP'],
    [longCode + 's', 2, 64, 'EM5ycrHS8h5SzK^n#WUk)KiTE4-MaeB+%EYKEeiKpom5h+UnGs2JjD7^@PN&rDA4'],
].map(([code,counter,length,pwd]) => ({ args: { master: 'synthetic long-code fixture', code, counter, length }, pwd }));
const originalCases = original.map(v=>({args:asRequest(v),pwd:v.pwd}));
let checks=0;
for (const [label,factory,expectedProvider,cases] of [
    ['source / WASM',spv2CoreFactory,'hash-wasm',[...golden,...fixedCases,...longCodeCases]],
    ['bundle / WASM',bundleFactory(true),'hash-wasm',[...golden,...fixedCases,...longCodeCases]],
    ['source / noble',loadCore({provider:null,console:quiet}).spv2CoreFactory,'noble-hashes',[...originalCases,...fixedCases,...longCodeCases]],
    ['bundle / noble',bundleFactory(false),'noble-hashes',[...originalCases,...fixedCases,...longCodeCases]],
]) {
    const engine=factory(null,false);
    for(const [index,c] of cases.entries()) {
        if(c.error) await assert.rejects(engine.derive(c.args),{message:c.error});
        else assert.equal((await engine.derive(c.args)).password,c.pwd,label+' case '+(index+1));
        checks++;
    }
    assert.equal(engine.provider(),expectedProvider,label+' must really use requested provider');checks++;
    // Real production providers must also survive object reuse and two
    // concurrent engines; these answers come from unchanged original vectors.
    const base=asRequest(original[0]), other=asRequest(original[1]);
    const reused={...base}, first=engine.derive(reused);
    Object.assign(reused,other);const second=engine.derive(reused);
    Object.assign(reused,{master:'not a submitted request',code:'not-submitted',counter:9999,length:6,mode:'pin'});
    const [firstResult,secondResult]=await Promise.all([first,second]);
    assert.equal(firstResult.password,original[0].pwd,label+' snapshots first queued request');checks++;
    assert.equal(secondResult.password,original[1].pwd,label+' snapshots second queued request');checks++;
    const peer=factory(null,false);
    try {
        const [a,b]=await Promise.all([engine.derive(base),peer.derive(other)]);
        assert.equal(a.password,original[0].pwd,label+' concurrent engine A');checks++;
        assert.equal(b.password,original[1].pwd,label+' concurrent engine B');checks++;
        await peer.wipeSession();
        assert.equal((await engine.derive(base)).cached,true,label+' peer wipe preserves A cache');checks++;
        await engine.wipeSession();const fresh=await engine.derive(base);
        assert.ok(!fresh.cached&&fresh.password===original[0].pwd,label+' real own wipe resets A cache');checks++;
    } finally { await peer.wipeSession(); }
    const nfd={...base,master:'cafe\u0301-secret',code:'  café-site  '};
    const nfc={...nfd,master:'café-secret',code:'café-site'};
    assert.equal((await engine.derive(nfd)).password,(await engine.derive(nfc)).password,label+' NFC/trim contract');checks++;
    assert.equal((await engine.derive(nfc)).cached,true,label+' canonical cache tag');checks++;
    await engine.wipeSession();
    assert.equal((await engine.derive(nfc)).cached,false,label+' awaitable cache wipe');checks++;
    await engine.wipeSession();
    console.log('PASS immutable compatibility:',label,'('+cases.length+' fixed cases plus provider/NFC/cache/queue/concurrency checks)');
}
console.log(`PASS production compatibility: ${checks} source/bundle, WASM/noble and fixed-answer checks`);
