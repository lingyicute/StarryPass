/* Fault/queue tests for production wrappers, NOT a second crypto implementation.
 * Production-size KDF is stubbed here; RFC KAT still uses real noble. Full
 * production parameters/answers are checked separately by verify_compat.mjs.
 */
import assert from 'node:assert/strict';
import { argon2id } from '@noble/hashes/argon2.js';
import { loadCore, cryptoProbe } from './helpers/load-core.mjs';

let checks = 0;
const check = (value, label) => { assert.ok(value, label); checks++; };
const reject = async (promise, pattern) => { await assert.rejects(promise, pattern); checks++; };
const zero = bytes => bytes && bytes.every(v => v === 0);
const args = { master:'public regression master 2026!', code:'example-site', tier:'standard', counter:1, length:16, mode:'full' };
const pause = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return {promise,resolve}; };

function fixture(extra = {}) {
    const probe = cryptoProbe();
    const warnings = [], tags = [];
    let calls = 0;
    function fakeKdf(password, salt, opts) {
        if (opts.m === 32) return argon2id(password, salt, opts); // actual RFC KAT
        calls++;
        const bytes = new Uint8Array(32).fill(11);
        tags.push(bytes);
        return bytes; // test double, never included in the shipped core
    }
    const loaded = loadCore({ ...probe, provider:null,
        argon2id:fakeKdf, argon2idAsync:async (...values) => fakeKdf(...values),
        console:{warn:message=>warnings.push(message)}, ...extra });
    return { ...probe, ...loaded, warnings, tags, calls:()=>calls };
}

// Strong-random generation must succeed before publishing a nonce. Failure must
// remain fail-closed on every request, not just the first one.
{
    const f=fixture(); const engine=f.spv2CoreFactory(null,false);
    await engine.derive(args); await engine.wipeSession();
    f.state.fail='random'; f.state.random.length=0; f.state.encoded.length=0;
    await reject(engine.derive(args),/RNG_UNAVAILABLE/);
    await reject(engine.derive(args),/RNG_UNAVAILABLE/);
    check(f.state.random.length===2,'CSPRNG retried instead of retaining failed nonce');
    check(f.state.random.every(zero),'partial random buffers cleared');
    check(f.state.encoded.every(zero),'CSPRNG failure clears encoded secrets');
    f.state.fail=null;
    check((await engine.derive(args)).cached===false,'random-source recovery starts a new cache');
    check((await engine.derive(args)).cached===true,'normal single-slot cache still works');
    await engine.wipeSession();
    check(f.tags.every(zero),'wipe erases retained session keys');
}
{
    const f=fixture();delete f.crypto.getRandomValues;
    const e=f.spv2CoreFactory(null,false);
    await reject(e.derive(args),/RNG_UNAVAILABLE/);
    await reject(e.derive(args),/RNG_UNAVAILABLE/);
    check(f.state.encoded.every(zero),'missing CSPRNG stays fail-closed and clears inputs');
}

// All async WebCrypto failure boundaries must run finally cleanup.
for (const fault of ['sign','digest','HKDF-import','deriveBits']) {
    const f=fixture();const e=f.spv2CoreFactory(null,false);
    await e.derive(args);
    f.state.messages.length=0; // exclude the public RFC KAT message
    f.state.fail=fault==='HKDF-import' ? (name,values)=>name==='importKey'&&values[2]==='HKDF' : fault;
    await reject(e.derive({...args,master:'changed secret for '+fault}),/INJECTED_/);
    check(f.state.encoded.every(zero),fault+' clears encoded master/code');
    check(f.state.messages.every(zero),fault+' clears HMAC messages');
    check(f.state.digestInputs.every(zero),fault+' clears framed salt input');
    check(f.state.rawBlocks.every(zero),fault+' clears native HKDF outputs');
    check(f.tags.every(zero),fault+' clears cached and unpublished KDF keys');
    check(f.state.hkdfKeys.every(zero),fault+' clears raw HKDF key buffers on failure');
    f.state.fail=null;
    check((await e.derive(args)).cached===false,fault+' recovers without stale cache');
    await e.wipeSession();
}
{
    let shouldFail=false;
    const f=fixture({argon2idAsync:async (password,salt,opts)=>{
        if(opts.m===32)return argon2id(password,salt,opts);
        if(shouldFail)throw new Error('INJECTED_ARGON');
        return new Uint8Array(32).fill(17);
    }});
    const e=f.spv2CoreFactory(null,false);await e.derive(args);shouldFail=true;
    await reject(e.derive({...args,master:'KDF failure secret'}),/INJECTED_ARGON/);
    check(f.state.encoded.every(zero),'KDF failure clears inputs');
    check(f.state.digestInputs.every(zero),'KDF failure clears salt framing');
    check(f.state.hkdfKeys.every(zero),'KDF failure clears previous cached key');
}

// Replacement and disposal must clear both native full HKDF output and slices.
{
    const f=fixture();const info=new Uint8Array([1,2,3]);const stream=new f.HkdfStream(info);
    await stream.init(new Uint8Array(32).fill(7));await stream.nextByte();const first=stream.buf;
    for(let i=0;i<32;i++)await stream.nextByte();const second=stream.buf;
    check(zero(first),'replaced HKDF block cleared immediately');
    check(f.state.rawBlocks.every(zero),'full native deriveBits outputs cleared immediately');
    stream.dispose();
    check(zero(second)&&zero(info),'dispose clears current block and info');
    check(stream.ikmKey===null,'dispose drops native CryptoKey reference');
}
{
    const f=fixture();const e=f.spv2CoreFactory(null,false);
    await e.derive(args);const first=f.state.hkdfKeys.at(-1);
    await e.derive({...args,master:'next public master'});
    check(zero(first),'cache replacement clears previous session key');
    check(!zero(f.state.hkdfKeys.at(-1)),'new cache key remains usable until wipe');
    await e.wipeSession();check(f.state.hkdfKeys.every(zero),'wipe clears all retained raw key buffers');
}

// Preserve production's documented golden-set fallbacks, while rejecting
// inherited table entries as choices (do not break bogus/ultra compatibility).
{
    const f=fixture();
    for(const value of [undefined,null,'bogus','ultra','constructor','__proto__','toString','hasOwnProperty']) {
        const input=f.canonicalizeInputs({...args,mode:value,tier:value});
        check(input.mode==='full'&&input.tierSpec.id===1,'unknown/prototype keys use original fallback');
        input.masterBytes.fill(0);input.codeBytes.fill(0);
    }
    Object.prototype.unlistedTestMode={id:99};
    try {check(f.canonicalizeInputs({...args,mode:'unlistedTestMode',tier:'unlistedTestMode'}).mode==='full','prototype pollution cannot select a mode');}
    finally{delete Object.prototype.unlistedTestMode;}
}

// Per-engine nonce isolation: wiping B must not invalidate A's cache.
{
    const f=fixture();const a=f.spv2CoreFactory(null,false),b=f.spv2CoreFactory(null,false);
    await a.derive(args);await b.derive({...args,master:'independent engine'});await b.wipeSession();
    check((await a.derive({...args,counter:2})).cached===true,'one engine wipe does not invalidate another engine cache');
    await a.wipeSession();check(f.state.random.every(zero),'both independent nonces cleared');
}

// Wipe returns an awaitable barrier and invalidates active + already queued jobs.
{
    const entered=pause(),release=pause(),tags=[];let productionCalls=0;
    const f=fixture({argon2idAsync:async(password,salt,opts)=>{
        if(opts.m===32)return argon2id(password,salt,opts);
        productionCalls++;
        if(productionCalls===1){entered.resolve();await release.promise;}
        const tag=new Uint8Array(32).fill(31);tags.push(tag);return tag;
    }});
    const e=f.spv2CoreFactory(null,false);
    const active=e.derive(args).then(()=>null,err=>err.message);
    const queued=e.derive({...args,code:'outdated queued input'}).then(()=>null,err=>err.message);
    await entered.promise;
    const wiped=e.wipeSession();check(typeof wiped?.then==='function','wipe returns completion Promise');
    const latest=e.derive({...args,code:'latest-after-wipe'});
    release.resolve();
    check(await active==='SESSION_WIPED','active pre-wipe result rejected');
    check(await queued==='SESSION_WIPED','queued pre-wipe job rejected before KDF');
    await wiped;const result=await latest;
    check(result.cached===false&&productionCalls===2,'only active + fresh jobs execute KDF');
    check(zero(tags[0]),'canceled in-flight key cleared');
    check((await e.derive({...args,code:'latest-after-wipe'})).cached===true,'fresh post-wipe session usable');
    await e.wipeSession();check(tags.every(zero),'barrier cleanup clears every test key');
}

// Provider gate failure is observable but never logs the failure's secret text.
for(const provider of [null,{argon2id:async()=>{throw new Error(args.master);}},{argon2id:async()=>new Uint8Array(32)},
    {argon2id:async()=>32},{argon2id:async()=>'32'},{argon2id:async()=>new Uint8Array(31)},
    {argon2id:async()=>Array.from(Buffer.from('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659','hex'))}]) {
    const f=fixture({provider});const e=f.spv2CoreFactory(null,false);
    await e.derive(args);await e.derive({...args,counter:2});
    check(e.provider()==='noble-hashes','unavailable/mismatched provider remains gated off');
    check(f.warnings.length===1&&!f.warnings[0].includes(args.master),'one nonsensitive provider diagnostic');
    await e.wipeSession();
}

// Failed boot HMAC must reset an already successful WASM cross-gate.
{
    const kat=Uint8Array.from(Buffer.from('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659','hex'));
    const f=fixture({provider:{argon2id:async()=>kat.slice()}});const e=f.spv2CoreFactory(null,false);
    f.state.fail='sign';await reject(e.derive(args),/INJECTED_sign/);
    check(e.provider()==='noble-hashes','failed boot resets WASM provider flag');
    f.state.fail=null;await e.derive(args);
    check(e.provider()==='hash-wasm','transient boot failure retries both self-tests');
    await e.wipeSession();
}
// A code-encoding failure after master allocation must also clear the master.
{
    const captured=[];
    class Encoder extends TextEncoder {
        encode(value) {
            if(value===args.code)throw new Error('INJECTED_encode');
            const bytes=super.encode(value);captured.push(bytes);return bytes;
        }
    }
    const f=fixture({TextEncoder:Encoder});const e=f.spv2CoreFactory(null,false);
    await reject(e.derive(args),/INJECTED_encode/);
    check(captured.length===1&&captured.every(zero),'partial canonicalisation clears master bytes');
}

// Worker wipe acknowledgment happens after cleanup, not merely after enqueueing.
{
    const f=fixture();const messages=[];const worker={postMessage:value=>messages.push(value)};
    f.spv2CoreFactory(worker,false);
    worker.onmessage({data:{...args,id:71,type:'derive'}});
    for(let n=0;!messages.some(x=>x.id===71);n++){assert.ok(n<1000);await new Promise(r=>setTimeout(r,1));}
    worker.onmessage({data:{id:72,type:'wipe'}});
    for(let n=0;!messages.some(x=>x.id===72);n++){assert.ok(n<1000);await new Promise(r=>setTimeout(r,1));}
    check(messages.find(x=>x.id===71).ok===true,'worker async derive response');
    check(messages.find(x=>x.id===72).type==='wiped'&&f.tags.every(zero),'worker acknowledges only completed wipe');
}
// Capture caller-owned requests before queued execution, including all six
// scalar fields. Reusing or mutating the object after derive() is supported.
{
    const encoded=[];
    class Encoder extends TextEncoder {
        encode(value) { encoded.push(value);return super.encode(value); }
    }
    const costs=[];
    const f=fixture({TextEncoder:Encoder,argon2idAsync:async(password,salt,opts)=>{
        if(opts.m===32)return argon2id(password,salt,opts);
        costs.push(opts.m);return new Uint8Array(32).fill(opts.m===65536?11:12);
    }});const e=f.spv2CoreFactory(null,false);
    const a={...args}, b={master:'second snapshot master',code:'second snapshot site',tier:'paranoid',counter:2,length:8,mode:'pin'};
    const expectedA=await e.derive(a),expectedB=await e.derive(b);
    encoded.length=0;
    const reused={...a};const first=e.derive(reused);
    Object.assign(reused,b);const second=e.derive(reused);
    Object.assign(reused,{master:'not requested master',code:'not requested site',tier:'standard',counter:3,length:20,mode:'alnum'});
    const [one,two]=await Promise.all([first,second]);
    check(one.password===expectedA.password,'queued first request retains its original scalar fields');
    check(two.password===expectedB.password,'queued second request retains its own scalar fields');
    check(encoded.includes(a.master)&&encoded.includes(a.code),'first master/code captured at call time');
    check(encoded.includes(b.master)&&encoded.includes(b.code),'second master/code captured at call time');
    check(!encoded.includes(reused.master)&&!encoded.includes(reused.code),'post-call master/code mutations never encoded');
    check(one.password.length===16&&/^\d{8}$/.test(two.password),'snapshot preserves mode and length');
    check(costs.join(',')==='65536,262144,65536,262144','snapshot preserves the captured tier cost and KDF/cache identity');
    await e.wipeSession();
}
{
    const f=fixture();const e=f.spv2CoreFactory(null,false);await e.derive(args);
    const oldKey=f.state.hkdfKeys.at(-1), fault=new Error('INJECTED_request_getter');
    const bad={...args,get code(){throw fault;}};
    let rejected;
    assert.doesNotThrow(()=>{rejected=e.derive(bad);});checks++;
    check(typeof rejected?.then==='function','snapshot field errors still return a Promise');
    const later=e.derive(args);
    await reject(rejected,/INJECTED_request_getter/);
    check(zero(oldKey),'snapshot error clears the preceding cached session key through finally');
    check((await later).cached===false,'snapshot error does not break FIFO or leak prior cache');
    for(const missing of [null,undefined,123,'raw-string',true,{master:Symbol('m'),code:'x'},{master:'x',code:Symbol('c')},
        {...args,counter:Symbol('n')},{...args,length:Symbol('l')}]) {
        let result;
        assert.doesNotThrow(()=>{result=e.derive(missing);});checks++;
        await reject(result,TypeError);
    }
    check((await e.derive({...args,length:0})).password.length===4,'zero length clamps to minimum 4');
    check((await e.derive({...args,length:'0'})).password.length===4,'string zero length clamps to minimum 4');
    check((await e.derive({...args,length:1e21})).password.length===64,'huge length clamps to maximum 64');
    check((await e.derive({...args,length:'1e2'})).password.length===64,'exponent string length clamps to maximum 64');
    check((await e.derive({...args,length:'1e500'})).password.length===64,'overflow exponent length clamps to maximum 64');
    check((await e.derive({...args,length:'-1e500'})).password.length===4,'negative overflow exponent length clamps to minimum 4');
    check((await e.derive({...args,length:9e-7})).password.length===4,'fractional sub-one exponent length clamps to minimum 4');
    check((await e.derive({...args,counter:'1e5'})).password===(await e.derive({...args,counter:9999})).password,'exponent counter clamps to 9999');
    check((await e.derive({...args,counter:'1e500'})).password===(await e.derive({...args,counter:9999})).password,'overflow exponent counter clamps to 9999');
    check((await e.derive({...args,counter:'-1e500'})).password===(await e.derive({...args,counter:1})).password,'negative overflow exponent counter clamps to 1');
    check((await e.derive({...args,counter:5e-7})).password===(await e.derive({...args,counter:1})).password,'fractional sub-one exponent counter clamps to 1');
    const falsy=await e.derive({get master(){throw null;}}).then(()=>({resolved:true}),reason=>({resolved:false,reason}));
    check(!falsy.resolved&&falsy.reason===null,'falsy thrown values are not mistaken for valid snapshots');
    const obsolete=e.derive(bad).then(()=>null,err=>err.message);
    await e.wipeSession();
    check(await obsolete==='SESSION_WIPED','wipe invalidation takes precedence over queued snapshot errors');
    check(f.state.encoded.every(zero),'request error and wipe paths clear encoded bytes');
}

// A provider that passed its public RFC boot KAT may still return malformed
// production output. Type-check BEFORE conversion (number 32 is not a key),
// require the protocol's exact 32-byte tag, clear byte views and drop the cache.
for(const lane of ['wasm','noble-local','noble-worker']) {
    const kat=Uint8Array.from(Buffer.from('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659','hex'));
    let output=new Uint8Array(32).fill(81);
    const fake=(password,salt,opts)=>opts.m===32?argon2id(password,salt,opts):output;
    const f=fixture({provider:lane==='wasm'?{argon2id:async opts=>opts.memorySize===32?kat.slice():output}:null,
        argon2id:fake,argon2idAsync:async(...values)=>fake(...values)});
    const e=f.spv2CoreFactory(lane==='noble-worker'?{postMessage(){}}:null,false);
    await e.derive(args);
    const cases=[new Uint8Array(0),new Uint8Array(31).fill(81),new Uint8Array(33).fill(81),
        new Uint8Array(31).fill(81).buffer,new Uint16Array(16).fill(0x5151),new Int8Array(32).fill(81),
        new Uint8ClampedArray(32).fill(81),new DataView(new Uint8Array(32).fill(81).buffer),
        32,'32',Array(32).fill(81),{length:32},null,undefined];
    for(let i=0;i<cases.length;i++) {
        output=cases[i];const malformed=output;
        const input={...args,master:args.master+' '+lane+' invalid '+i};
        await reject(e.derive(input),/INVALID_KDF_OUTPUT/);
        check(f.state.encoded.every(zero)&&f.state.hkdfKeys.every(zero),lane+' invalid tag clears inputs and previous key');
        if(ArrayBuffer.isView(malformed)||malformed instanceof ArrayBuffer) {
            const bytes=malformed instanceof ArrayBuffer?new Uint8Array(malformed):new Uint8Array(malformed.buffer,malformed.byteOffset,malformed.byteLength);
            check(zero(bytes),lane+' malformed binary output is cleared');
        }
        output=new Uint8Array(32).fill(81);
        check((await e.derive(input)).cached===false,lane+' recovery after invalid output starts a clean cache');
    }
    for(const [i,valid] of [new Uint8Array(32),new Uint8Array(32).fill(91).buffer,new Uint8Array(64).fill(91).subarray(16,48)].entries()) {
        output=valid;
        const result=await e.derive({...args,master:'valid binary tag '+lane+' '+i});
        check(result.password.length===16,lane+' accepts a valid 32-byte binary tag, including zeros');
        await e.wipeSession();
        const bytes=valid instanceof ArrayBuffer?new Uint8Array(valid):valid;
        check(zero(bytes),lane+' valid binary tag is cleared after wipe');
    }
}

// Worker response ids belong to the received envelope, not a later mutation.
{
    const f=fixture(),messages=[],worker={postMessage:value=>messages.push(value)};
    f.spv2CoreFactory(worker,false);
    const envelope={...args,id:101,type:'derive'};
    worker.onmessage({data:envelope});envelope.id=102;envelope.counter=9;
    for(let n=0;!messages.length;n++){assert.ok(n<1000);await new Promise(r=>setTimeout(r,1));}
    check(messages[0].id===101&&messages[0].ok===true,'Worker derive captures the received response id');
    const wipe={id:103,type:'wipe'};worker.onmessage({data:wipe});wipe.id=104;
    for(let n=0;messages.length<2;n++){assert.ok(n<1000);await new Promise(r=>setTimeout(r,1));}
    check(messages[1].id===103&&messages[1].type==='wiped','Worker wipe captures the received response id');
    worker.onmessage({data:{id:105,get type(){throw new Error('BAD_ENVELOPE');}}});
    check(messages[2].id===105&&messages[2].ok===false&&messages[2].error==='BAD_ENVELOPE',
        'Worker catches throwing envelope getters and replies with error');
}

// Failing to allocate the Argon2 matrix is reported as MEMORY_LIMIT (the UI's
// low-memory hint); other provider errors, and the later malformed-output
// check, keep their own codes. Covers all three provider lanes.
{
    const kat=argon2id(new Uint8Array(32).fill(1),new Uint8Array(16).fill(2),
        {t:3,m:32,p:4,dkLen:32,version:0x13,key:new Uint8Array(8).fill(3),personalization:new Uint8Array(12).fill(4)});
    const mem=()=>{throw new RangeError('Array buffer allocation failed');};
    for(const lane of ['wasm','noble','noble-worker']) {
        for(const [label,fault,expected] of [['allocation',mem,/^Error: MEMORY_LIMIT$/],
            ['other',()=>{throw new Error('INJECTED_KDF');},/INJECTED_KDF/]]) {
            let failing=false;
            const wasm=lane==='wasm'?{argon2id:async opts=>{if(opts.memorySize===32)return kat.slice();if(failing)fault();return new Uint8Array(32).fill(5);}}:null;
            const f=fixture({provider:wasm,
                argon2id:(password,salt,opts)=>{if(opts.m===32)return argon2id(password,salt,opts);if(failing)fault();return new Uint8Array(32).fill(5);},
                argon2idAsync:async(password,salt,opts)=>{if(opts.m===32)return argon2id(password,salt,opts);if(failing)fault();return new Uint8Array(32).fill(5);}});
            const e=f.spv2CoreFactory(lane==='noble-worker'?{postMessage(){}}:null,false);
            await e.derive(args);failing=true;
            await reject(e.derive({...args,master:'memory fault '+lane+label}),expected);
            check(f.state.encoded.every(zero),lane+' '+label+' KDF failure clears inputs');
            failing=false;
            check((await e.derive(args)).cached===false,lane+' '+label+' recovers with a clean cache');
            await e.wipeSession();
        }
    }
}

// Mutable object/array fields are coerced at derive() call time, not after queue delay,
// and failed boot KATs still zeroize their temporary KAT buffers.
{
    let oldTagZeroAtNextKdf=false;
    const f=fixture({argon2idAsync:async(password,salt,opts)=>{
        if(opts.m===32)return argon2id(password,salt,opts);
        if(f.tags.length===1)oldTagZeroAtNextKdf=zero(f.tags[0]);
        const bytes=new Uint8Array(32).fill(opts.m===262144?22:11);
        f.tags.push(bytes);
        return bytes;
    }});
    const e=f.spv2CoreFactory(null,false);
    const baseline=await e.derive(args);
    const pinParanoid=await e.derive({...args,tier:'paranoid',mode:'pin',length:6});
    check(oldTagZeroAtNextKdf,'cache miss zeroizes previous session key before starting next KDF');
    let tierReads=0,modeReads=0;
    const mutableMaster={val:args.master,toString(){return this.val;}};
    const mutableCode={val:args.code,toString(){return this.val;}};
    const mutableCounter={val:1,toString(){return String(this.val);}};
    const mutableLength={val:6,toString(){return String(this.val);}};
    const mutableTier={val:'paranoid',toString(){tierReads++;return this.val;}};
    const mutableMode={val:'pin',toString(){modeReads++;return this.val;}};
    const first=e.derive({...args,master:mutableMaster,code:mutableCode,counter:mutableCounter});
    const second=e.derive({...args,tier:mutableTier,mode:mutableMode,length:mutableLength});
    mutableMaster.val='mutated after call';mutableCode.val='mutated-site';mutableCounter.val=99;
    mutableTier.val='standard';mutableMode.val='full';mutableLength.val=24;
    check((await first).password===baseline.password,'boxed/object fields coerced at call time before queue execution');
    check((await second).password===pinParanoid.password,'boxed/object tier, mode and length coerced to primitives at call time');
    check(tierReads===1&&modeReads===1,'tier and mode objects are evaluated only once at snapshot time');
    const propReads={master:0,code:0,tier:0,mode:0,counter:0,length:0};
    const getterReq={
        get master(){propReads.master++;return args.master;},
        get code(){propReads.code++;return args.code;},
        get tier(){propReads.tier++;return args.tier;},
        get mode(){propReads.mode++;return args.mode;},
        get counter(){propReads.counter++;return args.counter;},
        get length(){propReads.length++;return args.length;},
    };
    check((await e.derive(getterReq)).password===baseline.password,'getter request derives baseline password');
    check(Object.values(propReads).every(v=>v===1),'each request property getter is read only once');
    await e.wipeSession();

    const katTags=[];
    const badKat=fixture({argon2idAsync:async()=>{const t=new Uint8Array(32).fill(99);katTags.push(t);return t;}});
    const badEngine=badKat.spv2CoreFactory(null,false);
    await reject(badEngine.derive(args),/KAT_ARGON2ID_FAILED/);
    check(katTags.length===1&&zero(katTags[0]),'failed Argon2 KAT still zeroizes its temporary tag');

    const noWarn=fixture({provider:null,console:{}});
    const noWarnEngine=noWarn.spv2CoreFactory(null,false);
    check((await noWarnEngine.derive(args)).password.length===16,'missing console.warn does not fail noble fallback');
    await noWarnEngine.wipeSession();

    let throwWarn=true;
    const faultyWarn=fixture({provider:null,console:{warn(){if(throwWarn)throw new Error('INJECTED_warn');}}});
    const faultyWarnEngine=faultyWarn.spv2CoreFactory(null,false);
    await reject(faultyWarnEngine.derive(args),/INJECTED_warn/);
    throwWarn=false;
    check((await faultyWarnEngine.derive(args)).password.length===16,'rejected wasmGatePromise resets and recovers on retry');
    await faultyWarnEngine.wipeSession();
}

// Insecure contexts have no crypto.subtle: report a stable error code, not a TypeError.
{
    const f=fixture({crypto:{getRandomValues:bytes=>bytes}});const e=f.spv2CoreFactory(null,false);
    await reject(e.derive(args),/^Error: WEBCRYPTO_UNAVAILABLE$/);
    await reject(e.derive(args),/WEBCRYPTO_UNAVAILABLE/);
    await e.wipeSession();
}

// An explicit forcePureJs request must bypass a gate-approved WASM provider,
// while the default engine still uses it.
{
    const kat=Uint8Array.from(Buffer.from('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659','hex'));
    let wasmCalls=0,katCalls=0;
    const provider={argon2id:async opts=>{if(opts.memorySize===32){katCalls++;return kat.slice();}wasmCalls++;return new Uint8Array(32).fill(7);}};
    const f=fixture({provider});
    const wasm=f.spv2CoreFactory(null,false),pure=f.spv2CoreFactory(null,true),loose=f.spv2CoreFactory(null,'true');
    const purePwd=(await pure.derive(args)).password;
    check(pure.provider()==='noble-hashes'&&katCalls===0&&wasmCalls===0&&f.calls()===1&&f.warnings.length===0,'forcePureJs engine never touches WASM provider even on cold boot');
    const wasmPwd=(await wasm.derive(args)).password;
    check(wasm.provider()==='hash-wasm'&&katCalls===1&&wasmCalls===1,'default engine runs WASM cross-gate and uses the gated WASM provider');
    check(purePwd!==wasmPwd,'forced pure-JS derivation really ran through the noble path');
    await loose.derive(args);
    check(loose.provider()==='hash-wasm'&&wasmCalls===2,'only boolean true forces pure JS');
    await Promise.all([wasm.wipeSession(),pure.wipeSession(),loose.wipeSession()]);
}

{
    // Worker + pure JS: without a JIT noble can run for minutes, so the Worker
    // reports progress (at most once a second) for the page's stall watchdog.
    const realNow = Date.now; let fake = 0;
    const kdf = (password, salt, opts) => {
        if (opts.m === 32) return argon2id(password, salt, opts); // actual RFC KAT
        for (let i = 0; i < 6; i++) { fake += 400; if (opts.onProgress) opts.onProgress(i / 6); }
        return new Uint8Array(32).fill(9);
    };
    const messages = [], worker = { postMessage: value => messages.push(value) };
    loadCore({ argon2id: kdf, provider: null }).spv2CoreFactory(worker, false);
    Date.now = () => fake;
    try {
        worker.onmessage({ data: { ...args, id: 501, type: 'derive', heartbeat: true } });
        for (let n = 0; !messages.some(x => x.id === 501 && x.ok !== undefined); n++) { assert.ok(n < 1000); await new Promise(r => setTimeout(r, 1)); }
        worker.onmessage({ data: { ...args, master: args.master + '!', id: 502, type: 'derive' } });
        for (let n = 0; !messages.some(x => x.id === 502); n++) { assert.ok(n < 1000); await new Promise(r => setTimeout(r, 1)); }
    } finally { Date.now = realNow; }
    const beats = messages.filter(x => x.type === 'progress');
    check(beats.length === 2 && beats.every(x => x.id === 501), 'pure-JS Worker heartbeats are throttled to one per second');
    check(messages[2].id === 501 && messages[2].ok === true, 'heartbeats precede the single derive result');
    check(messages.length === 4 && messages[3].id === 502 && messages[3].ok === true, 'no heartbeat unless the page opts in');
}

// HKDF output must have exactly the requested length: a short or long native result
// would otherwise be sliced into a misaligned block and silently change the password.
for (const delta of [-8, 8]) {
    const f = fixture();
    const native = f.crypto.subtle.deriveBits;
    const outputs = [];
    f.crypto.subtle.deriveBits = async (alg, key, bits) => {
        const out = new Uint8Array(await native(alg, key, bits));
        if (bits <= 256) return out.buffer;
        const bad = new Uint8Array(out.length + delta);
        bad.set(out.subarray(0, Math.min(out.length, bad.length)));
        out.fill(0);
        outputs.push(bad);
        return bad.buffer;
    };
    const stream = new f.HkdfStream(new Uint8Array([1, 2, 3]));
    await stream.init(new Uint8Array(32).fill(7));
    for (let i = 0; i < 32; i++) await stream.nextByte();
    await reject(stream.nextByte(), /INVALID_HKDF_OUTPUT/);
    check(outputs.length === 1 && outputs.every(zero), 'rejected HKDF output is cleared');
    stream.dispose();
}

console.log(`PASS production core: ${checks} cache, CSPRNG, cleanup, provider and async-wipe checks`);
