async () => {
    const src = `importScripts('libsodium.js');
      self.postMessage({type:'ready', globals: Object.keys(self).filter(k => /heap|memory|MEM|asm|wasm|Module/i.test(k))});`;
    const url = URL.createObjectURL(new Blob([src], {type:'application/javascript'}));
    const w = new Worker(url);
    const info = await new Promise((res) => { w.onmessage = (m) => res(m.data); });
    // On the main thread libsodium is already loaded; inspect its globals too.
    const mainGlobals = Object.keys(self).filter(k => /heap|memory|MEM|asm|wasm|Module/i.test(k));
    let mainKeys = null;
    if (typeof sodium !== 'undefined') {
        mainKeys = Object.keys(sodium).filter(k => /mem|heap|asm|wasm|alloc/i.test(k));
    }
    w.terminate(); URL.revokeObjectURL(url);
    return { workerGlobals: info.globals, mainGlobals, sodiumKeys: mainKeys,
             hasPerfMem: typeof performance !== 'undefined' && !!performance.memory };
}