export const maxDuration = 300;
const TF = { 'X-API-Key': process.env.TINYFISH_API_KEY || '' };
const img = (d: string) => { const [m, b] = d.split(','); return { type: 'image', source: { type: 'base64', media_type: m.match(/:(.*?);/)![1], data: b } }; };
const clamp = (n: number) => Math.max(0, Math.min(100, Math.round(n)));

async function claude(content: any[]) {
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY || '', 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5', max_tokens: 1500, messages: [{ role: 'user', content }] }),
    });
    const j = await r.json(); const m = (j.content?.[0]?.text || '').match(/\{[\s\S]*\}/);
    return m ? JSON.parse(m[0]) : {};
  } catch { return {}; }
}

export async function POST(req: Request) {
  const { doc, selfie, source, portal, f } = await req.json();
  const enc = new TextEncoder();
  return new Response(new ReadableStream({
    async start(ctl) {
      const send = (o: any) => ctl.enqueue(enc.encode(JSON.stringify(o) + '\n'));
      const log = (m: string) => send({ t: 'log', m });
      const sigs: { name: string; risk: number; weight: number; evidence: string }[] = [];
      try {
        log('Reading document with vision OCR...');
        const ex = await claude([img(doc), ...(selfie ? [img(selfie)] : []),
          { type: 'text', text: `You are a document forensics examiner. Image 1 is an ID/certificate${selfie ? '; image 2 is a live selfie of the person presenting it' : ''}. Return ONLY JSON: {"docType":"","fullName":"","idNumber":"","dob":"","issuer":"","country":"","expiry":"","inconsistencies":["cross-field problems e.g. dob vs id number, wrong format, expired, font/alignment mismatch"],"visualFlags":["signs of editing: pasted text, uneven fonts/kerning, blur halos, cloned areas, missing security features, photo-edge artifacts"],"tamperScore":0-100,"faceMatch":${selfie ? '0-100 similarity of ID photo to selfie' : 'null'}}` }]);
        log(`Extracted: ${ex.docType || 'unknown document'} / ${ex.issuer || 'unknown issuer'}`);
        sigs.push({ name: 'Visual tampering (AI vision)', risk: clamp(ex.tamperScore ?? 50), weight: 0.25, evidence: (ex.visualFlags || []).join('; ') || 'No visual anomalies reported' });
        sigs.push({ name: 'Pixel forensics (ELA)', risk: clamp((f.hotspot - 2.5) * 25), weight: 0.15, evidence: `Hotspot ratio ${f.hotspot.toFixed(2)}; local recompression spikes suggest edited regions` });
        const ed = /photoshop|gimp|canva|pixlr|affinity|snapseed|picsart|lightroom/i.test(f.software || '');
        sigs.push({ name: 'Metadata (EXIF)', risk: ed ? 95 : f.hasExif ? 10 : source === 'camera' ? 10 : 45, weight: 0.1, evidence: ed ? `Edited with ${f.software}` : f.hasExif ? 'Camera metadata present' : source === 'camera' ? 'Live capture, no file metadata expected' : 'Metadata stripped, common in re-saved or edited files' });
        sigs.push({ name: 'Capture authenticity', risk: source === 'camera' ? (f.sharp < 40 ? 55 : 8) : 40, weight: 0.1, evidence: source === 'camera' ? `Live camera capture (sharpness ${Math.round(f.sharp)})` : 'Uploaded file, not captured live' });
        sigs.push({ name: 'Cross-field consistency', risk: clamp((ex.inconsistencies || []).length * 30), weight: 0.15, evidence: (ex.inconsistencies || []).join('; ') || 'Fields are internally consistent' });
        if (selfie) sigs.push({ name: 'Live face match', risk: clamp(100 - (ex.faceMatch ?? 50)), weight: 0.15, evidence: `ID photo vs live selfie similarity ${ex.faceMatch ?? '?'}%` });

        let web = { risk: 50, evidence: 'No public sources found for this issuer' };
        if (ex.issuer) {
          log('TinyFish Search: locating official sources...');
          const q = `${ex.issuer} ${ex.country || ''} ${ex.docType || 'ID'} official verification number format`;
          const s = await fetch('https://api.search.tinyfish.ai?query=' + encodeURIComponent(q), { headers: TF }).then(r => r.json()).catch(() => ({}));
          const urls: string[] = (s.results || []).slice(0, 3).map((r: any) => r.url);
          log(`TinyFish Search: ${urls.length} sources`);
          if (urls.length) {
            log('TinyFish Fetch: reading pages (JS rendered)...');
            const p = await fetch('https://api.fetch.tinyfish.ai', { method: 'POST', headers: { ...TF, 'content-type': 'application/json' }, body: JSON.stringify({ urls, format: 'markdown' }) }).then(r => r.json()).catch(() => ({}));
            const text = (p.results || []).map((r: any) => `SOURCE ${r.url}\n${r.text}`).join('\n\n').slice(0, 12000);
            const v = await claude([{ type: 'text', text: `Public web pages:\n${text}\n\nDocument fields: ${JSON.stringify({ docType: ex.docType, idNumber: ex.idNumber, dob: ex.dob, issuer: ex.issuer, expiry: ex.expiry })}\nReturn ONLY JSON {"issuerExists":bool,"formatValid":bool|null,"contradictions":["..."],"summary":""}. Judge only from the pages.` }]);
            web = { risk: clamp((v.issuerExists === false ? 40 : 0) + (v.formatValid === false ? 35 : 0) + (v.contradictions?.length || 0) * 25 + (text ? 0 : 50)), evidence: v.summary || 'Sources reviewed' };
          }
        }
        sigs.push({ name: 'Live web verification (TinyFish Search + Fetch)', risk: web.risk, weight: 0.2, evidence: web.evidence });

        if (portal) {
          log('TinyFish Agent: navigating verification portal...');
          const res = await fetch('https://agent.tinyfish.ai/v1/automation/run-sse', { method: 'POST', headers: { ...TF, 'content-type': 'application/json' },
            body: JSON.stringify({ url: portal, goal: `Verify this record on the page: name "${ex.fullName}", ID/certificate number "${ex.idNumber}". Do not submit payments or create accounts. Return JSON {"found":true|false,"nameMatches":true|false,"details":"short"}` }) });
          const rd = res.body!.getReader(); const dec = new TextDecoder(); let buf = '', out: any = null;
          for (;;) {
            const { done, value } = await rd.read(); if (done) break;
            buf += dec.decode(value, { stream: true }); const lines = buf.split('\n'); buf = lines.pop() || '';
            for (const l of lines) if (l.startsWith('data:')) { try { const e = JSON.parse(l.slice(5)); log('Agent: ' + (e.purpose || e.type || 'working')); out = e.resultJson ?? e.result ?? out; } catch {} }
          }
          if (typeof out === 'string') { try { out = JSON.parse(out); } catch {} }
          const ok = out && out.found === true && out.nameMatches !== false;
          sigs.push({ name: 'Portal verification (TinyFish Agent)', risk: !out || out.found === undefined ? 50 : ok ? 5 : 90, weight: 0.25, evidence: out?.details || 'Agent finished without a clear match result' });
        }
        const w = sigs.reduce((a, s) => a + s.weight, 0);
        const score = clamp(sigs.reduce((a, s) => a + s.risk * s.weight, 0) / w);
        send({ t: 'result', score, verdict: score < 30 ? 'Low risk' : score < 60 ? 'Needs manual review' : 'High risk', signals: sigs, fields: { name: ex.fullName, id: ex.idNumber, dob: ex.dob, issuer: ex.issuer, type: ex.docType } });
      } catch (e: any) { send({ t: 'error', m: String(e?.message || e) }); }
      ctl.close();
    },
  }), { headers: { 'content-type': 'application/x-ndjson' } });
}
