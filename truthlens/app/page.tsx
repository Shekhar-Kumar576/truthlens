'use client';
import { useRef, useState } from 'react';

const load = (s: string) => new Promise<HTMLImageElement>((ok, no) => { const i = new Image(); i.onload = () => ok(i); i.onerror = no; i.src = s; });
async function shrink(s: string, max = 1400) {
  const i = await load(s), k = Math.min(1, max / Math.max(i.width, i.height));
  const c = document.createElement('canvas'); c.width = i.width * k; c.height = i.height * k;
  c.getContext('2d')!.drawImage(i, 0, 0, c.width, c.height); return c.toDataURL('image/jpeg', 0.85);
}
async function forensics(s: string, file?: File) {
  const i = await load(s), k = Math.min(1, 800 / Math.max(i.width, i.height));
  const w = Math.round(i.width * k), h = Math.round(i.height * k);
  const c = document.createElement('canvas'); c.width = w; c.height = h;
  const x = c.getContext('2d', { willReadFrequently: true })!; x.drawImage(i, 0, 0, w, h);
  const a = x.getImageData(0, 0, w, h).data;
  const j = await load(c.toDataURL('image/jpeg', 0.75)); x.drawImage(j, 0, 0, w, h);
  const b = x.getImageData(0, 0, w, h).data;
  const bw = Math.ceil(w / 16), bl = new Float32Array(bw * Math.ceil(h / 16)), cn = new Float32Array(bl.length);
  const g = new Float32Array(w * h);
  for (let p = 0; p < a.length; p += 4) {
    const n = p / 4, bi = Math.floor(n / w / 16) * bw + Math.floor((n % w) / 16);
    bl[bi] += (Math.abs(a[p] - b[p]) + Math.abs(a[p + 1] - b[p + 1]) + Math.abs(a[p + 2] - b[p + 2])) / 3; cn[bi]++;
    g[n] = 0.3 * a[p] + 0.59 * a[p + 1] + 0.11 * a[p + 2];
  }
  let sum = 0, max = 0; bl.forEach((v, n) => { const m = v / (cn[n] || 1); sum += m; if (m > max) max = m; });
  let ls = 0, lq = 0, N = 0;
  for (let y = 1; y < h - 1; y++) for (let xx = 1; xx < w - 1; xx++) { const n = y * w + xx, l = 4 * g[n] - g[n - 1] - g[n + 1] - g[n - w] - g[n + w]; ls += l; lq += l * l; N++; }
  const ex = file ? await (await import('exifr')).parse(file).catch(() => null) : null;
  return { hotspot: max / (sum / bl.length + 0.5), sharp: lq / N - (ls / N) ** 2, software: ex?.Software || '', hasExif: !!ex };
}

function Cam({ label, facing, onShot }: { label: string; facing: string; onShot: (d: string) => void }) {
  const v = useRef<HTMLVideoElement>(null); const [on, setOn] = useState(false);
  async function open() {
    try {
      const s = await navigator.mediaDevices.getUserMedia({ video: { facingMode: facing } });
      v.current!.srcObject = s; await v.current!.play(); setOn(true);
    } catch { alert('Camera access was blocked. Allow camera permission and try again.'); }
  }
  function snap() {
    const el = v.current!, c = document.createElement('canvas'); c.width = el.videoWidth; c.height = el.videoHeight;
    c.getContext('2d')!.drawImage(el, 0, 0); (el.srcObject as MediaStream).getTracks().forEach(t => t.stop());
    setOn(false); onShot(c.toDataURL('image/jpeg', 0.9));
  }
  return <div><video ref={v} playsInline muted className={on ? 'vid' : 'hide'} />
    {on ? <button className="btn" onClick={snap}>Capture {label}</button> : <button className="btn ghost" onClick={open}>Use camera</button>}</div>;
}

export default function Home() {
  const [doc, setDoc] = useState<{ src: string; file?: File; source: string } | null>(null);
  const [selfie, setSelfie] = useState(''); const [portal, setPortal] = useState('');
  const [logs, setLogs] = useState<string[]>([]); const [res, setRes] = useState<any>(null); const [busy, setBusy] = useState(false);

  function pick(f?: File) { if (f) { const r = new FileReader(); r.onload = () => setDoc({ src: r.result as string, file: f, source: 'upload' }); r.readAsDataURL(f); } }
  async function run() {
    if (!doc) return; setBusy(true); setRes(null); setLogs(['Preparing image and running pixel forensics...']);
    try {
      const [d, s, f] = await Promise.all([shrink(doc.src), selfie ? shrink(selfie) : '', forensics(doc.src, doc.file)]);
      const r = await fetch('/api/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ doc: d, selfie: s || undefined, source: doc.source, portal: portal || undefined, f }) });
      const rd = r.body!.getReader(), dec = new TextDecoder(); let buf = '';
      for (;;) {
        const { done, value } = await rd.read(); if (done) break;
        buf += dec.decode(value, { stream: true }); const ls = buf.split('\n'); buf = ls.pop() || '';
        for (const l of ls) { if (!l) continue; const e = JSON.parse(l);
          if (e.t === 'log') setLogs(p => [...p, e.m]); else if (e.t === 'result') setRes(e); else if (e.t === 'error') setLogs(p => [...p, 'Error: ' + e.m]); }
      }
    } catch (e: any) { setLogs(p => [...p, 'Error: ' + e.message]); }
    setBusy(false);
  }
  const col = res ? (res.score < 30 ? '#2ee59d' : res.score < 60 ? '#ffb84d' : '#ff5d73') : '#18d6e0';
  return <main>
    <h1>Catch fake IDs before they <span>get through</span></h1>
    <p className="sub">Upload or capture a document. TruthLens checks the image for edits, compares the fields, and verifies them against live public sources with TinyFish. You get a risk score with the evidence behind it.</p>
    <div className="grid">
      <div className="card"><h3>1. Document</h3><p>ID card, marksheet or certificate.</p>
        <div className="row"><label className="btn ghost">Upload image<input type="file" accept="image/*" hidden onChange={e => pick(e.target.files?.[0])} /></label>
          <Cam label="document" facing="environment" onShot={d => setDoc({ src: d, source: 'camera' })} /></div>
        {doc && <img className="thumb" src={doc.src} alt="Document preview" />}</div>
      <div className="card"><h3>2. Live selfie (optional)</h3><p>Matched against the photo on the document.</p>
        <Cam label="selfie" facing="user" onShot={setSelfie} />{selfie && <img className="thumb" src={selfie} alt="Selfie preview" />}</div>
      <div className="card"><h3>3. Portal check (optional)</h3><p>Public verification page for the TinyFish agent to open.</p>
        <input type="text" placeholder="https://verify.example.gov/..." value={portal} onChange={e => setPortal(e.target.value)} /></div>
    </div>
    <div className="row" style={{ margin: '24px 0' }}><button className="btn" disabled={!doc || busy} onClick={run}>{busy ? 'Screening...' : 'Screen document'}</button></div>
    {logs.length > 0 && <div className="card" style={{ marginBottom: 16 }}><div className="log">{logs.join('\n')}</div></div>}
    {res && <div className="card res">
      <div className="ring" style={{ ['--p' as any]: res.score, ['--c' as any]: col }}><div><span><b>{res.score}</b><small>{res.verdict}</small></span></div></div>
      <div><h3>Why this score</h3>
        {res.signals.map((s: any) => <div className="sig" key={s.name}><div className="top"><span>{s.name}</span><span>{s.risk}/100</span></div><div className="bar"><i style={{ width: s.risk + '%' }} /></div><p>{s.evidence}</p></div>)}</div>
    </div>}
  </main>;
}
