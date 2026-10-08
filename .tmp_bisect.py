"""Isolate what makes the shipped worker saturate at ~2.3x.

Pure keygen in this same browser scales 7.7x at 8 workers. The shipped worker
scales 2.3x. The difference must be something the shipped loop does that the
synthetic one does not. Candidates, tested one at a time:
  * the byte-walk + nibble matching (pure JS work)
  * postMessage progress reporting
  * the 30ms yield via setTimeout
"""
import statistics
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


# Variants of the hot loop. All do the same keygen; they differ only in which
# extra cost is included, so the scaling difference isolates the cause.
VARIANTS = {
    "keygen only": """
        const seed = new Uint8Array(32);
        const N = 40000;
        const run = () => { const t0 = performance.now();
            for (let i = 0; i < N; i++) { seed[0]=i&0xff; seed[1]=(i>>>8)&0xff; seed[2]=(i>>>16)&0xff;
                sodium.crypto_sign_seed_keypair(seed); }
            return N / ((performance.now()-t0)/1000); };
        run(4000);
        const s=[run(),run(),run()];
        self.postMessage({kps: Math.max(...s)});
    """,
    "keygen + walk + match": """
        const seed = new Uint8Array(32);
        const pub = new Uint8Array(32);
        const N = 40000;
        const HEXNIB = new Int8Array(256).fill(-1);
        for (let i=0;i<10;i++) HEXNIB[48+i]=i;
        for (let i=0;i<6;i++) HEXNIB[97+i]=10+i;
        const decode = (hex) => { const o=new Uint8Array(hex.length);
            for (let i=0;i<hex.length;i++) o[i]=HEXNIB[hex.charCodeAt(i)]&0xff; return o; };
        const pat = decode('ffffffffffffffff');
        const startsWithNibbles = (bytes, nib, n) => {
            for (let i=0;i<n;i++) if ((bytes[i>>1] >> (i&1 ? 0 : 4)) & 0x0f !== nib[i]) return false;
            return true; };
        const run = () => { const t0=performance.now();
            for (let i=0;i<N;i++) { seed[0]=i&0xff; seed[1]=(i>>>8)&0xff; seed[2]=(i>>>16)&0xff;
                const kp = sodium.crypto_sign_seed_keypair(seed);
                startsWithNibbles(kp.publicKey, pat, 16);
                const bb = seed[31]; seed[31]=(bb+1)&0xff; if(seed[31]===0){seed[30]=(seed[30]+1)&0xff;} }
            return N/((performance.now()-t0)/1000); };
        run(4000);
        const s=[run(),run(),run()];
        self.postMessage({kps: Math.max(...s)});
    """,
    "keygen + yield every 30ms": """
        const seed = new Uint8Array(32);
        let attempts = 0;
        let lastYield = Date.now();
        self.postMessage({type:'ready'});
        self.onmessage = async () => {
            const t0 = performance.now();
            const N = 40000;
            let done = 0;
            while (done < N) {
                for (let b=0;b<256 && done<N;b++) { seed[0]=done&0xff; seed[1]=(done>>>8)&0xff;
                    sodium.crypto_sign_seed_keypair(seed); done++; }
                const now = Date.now();
                if (now - lastYield >= 30) { lastYield = now;
                    await new Promise(r=>setTimeout(r,0)); }
            }
            const kps = N/((performance.now()-t0)/1000);
            self.postMessage({kps, attempts: done});
        };
    """,
    "keygen + yield + postMessage": """
        const seed = new Uint8Array(32);
        let attempts = 0;
        let lastYield = Date.now();
        let lastReport = 0;
        const report = (force) => { const now=Date.now();
            if (!force && now-lastReport < 500) return;
            self.postMessage({type:'progress', attempts, rate:0, progress:0, expectedAttempts:1e12});
            lastReport = now; };
        report(true);
        self.onmessage = async () => {
            const t0 = performance.now();
            const N = 40000;
            let done = 0;
            while (done < N) {
                for (let b=0;b<256 && done<N;b++) { seed[0]=done&0xff; seed[1]=(done>>>8)&0xff;
                    sodium.crypto_sign_seed_keypair(seed); done++; attempts++; }
                report(false);
                const now = Date.now();
                if (now - lastYield >= 30) { lastYield = now;
                    await new Promise(r=>setTimeout(r,0)); }
            }
            const kps = N/((performance.now()-t0)/1000);
            self.postMessage({kps, attempts: done});
        };
    """,
}

TEMPLATE = """
const LIB = self.__LIB__;
const BODY = self.__BODY__;
importScripts(LIB);
(async () => {
    await sodium.ready;
    (new Function(BODY))();
})();
"""

handler = partial(Quiet, directory=str(ROOT))
httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
PORT = httpd.server_address[1]

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    page.goto(f"http://127.0.0.1:{PORT}/index.html", wait_until="load")
    page.wait_for_function("() => typeof sodium !== 'undefined' && sodium.ready")
    lib = page.evaluate("() => new URL('libsodium.js', location.href).href")

    print(f"{'variant':>28} {'1w':>10} {'4w':>10} {'8w':>10} {'8w speedup':>11}")
    for name, body in VARIANTS.items():
        src = ("self.__LIB__ = %r;\nself.__BODY__ = %r;\n%s" % (lib, body, TEMPLATE))
        out = {}
        for n in (1, 4, 8):
            trials = []
            for _ in range(2):
                if "onmessage" in body:
                    page.evaluate("""
                        (cfg) => {
                            window.__done=false; window.__kps=0;
                            const u = URL.createObjectURL(new Blob([cfg.src],{type:'application/javascript'}));
                            window.__ws=[];
                            window.__total=0;
                            for(let i=0;i<cfg.n;i++){
                                const w=new Worker(u); window.__ws.push(w);
                                w.onmessage=(e)=>{ if(e.data.kps) window.__total+=e.data.kps; };
                            }
                            window.__wurl=u;
                            setTimeout(()=>{
                                for(const w of window.__ws){ w.onmessage=()=>{}; w.postMessage({go:1}); }
                                window.__t0=performance.now();
                                setTimeout(()=>{
                                    window.__kps=window.__total;
                                    for(const w of window.__ws) w.terminate();
                                    URL.revokeObjectURL(u);
                                    window.__done=true;
                                }, 6000);
                            }, 1200);
                        }
                    """, {"src": src, "n": n})
                else:
                    page.evaluate("""
                        (cfg) => {
                            window.__done=false; window.__total=0;
                            const u = URL.createObjectURL(new Blob([cfg.src],{type:'application/javascript'}));
                            const ws=[]; let got=0;
                            for(let i=0;i<cfg.n;i++){
                                const w=new Worker(u); ws.push(w);
                                w.onmessage=(e)=>{ if(e.data.kps){ window.__total+=e.data.kps; if(++got>=cfg.n) window.__done=true; } };
                            }
                            window.__wurl=u; window.__ws=ws;
                        }
                    """, {"src": src, "n": n})
                try:
                    page.wait_for_function("() => window.__done === true", timeout=40000)
                except Exception:
                    pass
                k = page.evaluate("() => window.__total || 0")
                if k:
                    trials.append(k)
                time.sleep(0.3)
            out[n] = statistics.median(trials) if trials else 0
        base = out.get(1, 0) or 1
        print(f"{name:>28} {out.get(1,0):>10,.0f} {out.get(4,0):>10,.0f} {out.get(8,0):>10,.0f} {out.get(8,0)/base:>10.2f}x")
    b.close()

httpd.shutdown()