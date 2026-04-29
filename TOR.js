import { connect } from 'cloudflare:sockets';
import TlsClient from '../../TLS/TLSClientMini.js';
const uuid = '2523c510-9ff0-415b-9582-93949bfae7e3', maxED = 8192, cry = crypto.subtle;
const enc = new TextEncoder(), dec = new TextDecoder(), idB = Uint8Array.from(uuid.replaceAll('-', '').match(/../g), x => parseInt(x, 16));
const asU8 = x => x instanceof Uint8Array ? x : ArrayBuffer.isView(x) ? new Uint8Array(x.buffer, x.byteOffset, x.byteLength) : x instanceof ArrayBuffer ? new Uint8Array(x) : x;
const u8 = (...xs) => Uint8Array.from(xs.flatMap(x => x == null ? [] : typeof x === 'number' ? [x & 255] : [...asU8(x)]));
const cat = (...xs) => { const r = new Uint8Array(xs.reduce((n, x) => n + (x?.length ?? 0), 0)); xs.reduce((o, x) => (x?.length && r.set(asU8(x), o), o + (x?.length ?? 0)), 0); return r; };
const [en, de] = [s => enc.encode(s), b => dec.decode(b)], u16 = n => [(n >> 8) & 255, n & 255], u32 = n => [(n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
const b64u8 = (s, url = 0) => Uint8Array.from(atob((url ? s.replace(/-/g, '+').replace(/_/g, '/') : s).padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0));
const b64d = s => b64u8(s, 1), u8hex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase(), esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const addr = (t, b) => t === 3 ? de(b) : t === 1 ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}` : `[${Array.from({ length: 8 }, (_, i) => ((b[i * 2] << 8) | b[i * 2 + 1]).toString(16)).join(':')}]`;
const parseAddr = (b, o, t) => { const l = t === 3 ? b[o++] : t === 1 ? 4 : t === 4 ? 16 : null, n = o + (l ?? 0); return l != null && n <= b.length ? { addrBytes: b.subarray(o, n), dataOffset: n } : null; };
const vless = c => idB.every((b, i) => c[i + 1] === b) && (() => { const o = 19 + c[17], port = (c[o] << 8) | c[o + 1], t = c[o + 2] === 1 ? 1 : c[o + 2] + 1, a = parseAddr(c, o + 3, t); return a && { addrType: t, ...a, port }; })();
const toU8 = d => d instanceof Uint8Array ? d : new Uint8Array(d instanceof ArrayBuffer ? d : d.buffer ?? d);
const relay = async (rd, send, close) => { try { for (;;) { const { done, value } = await rd.read(); if (done) break; value?.byteLength && send(value); } } catch {} finally { try { rd.releaseLock(); } catch {} close(); } };
const first = fs => fs.reduce((p, f) => p.then(v => v ?? f().catch(() => null)), Promise.resolve(null));
const pick = a => a[Math.random() * a.length | 0];
const hmac256 = async (k, m) => new Uint8Array(await cry.sign('HMAC', await cry.importKey('raw', k, { name: 'HMAC', hash: 'SHA-256' }, 0, ['sign']), m));
const HK = new Map(), hmaci = async (k, m) => new Uint8Array(await cry.sign('HMAC', await (HK.get(k) ?? (HK.set(k, cry.importKey('raw', NTOR[k], { name: 'HMAC', hash: 'SHA-256' }, 0, ['sign'])), HK.get(k))), m));
class Sha1 {
  constructor(seed) { Object.assign(this, { h0: 0x67452301, h1: 0xefcdab89, h2: 0x98badcfe, h3: 0x10325476, h4: 0xc3d2e1f0, buf: new Uint8Array(64), bufLen: 0, bytes: 0, w: new Uint32Array(80) }); seed?.length && this.update(seed); }
  clone() { const s = new Sha1(); return Object.assign(s, { h0: this.h0, h1: this.h1, h2: this.h2, h3: this.h3, h4: this.h4, bufLen: this.bufLen, bytes: this.bytes }), s.buf.set(this.buf.subarray(0, this.bufLen)), s; }
  _blk(b, o = 0) {
    const { w } = this;
    for (let i = 0; i < 16; i++, o += 4) w[i] = ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
    for (let i = 16; i < 80; i++) { const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]; w[i] = ((x << 1) | (x >>> 31)) >>> 0; }
    let [a, b0, c, d, e] = [this.h0, this.h1, this.h2, this.h3, this.h4];
    for (let i = 0; i < 80; i++) { const f = i < 20 ? (b0 & c) | (~b0 & d) : i < 40 ? b0 ^ c ^ d : i < 60 ? (b0 & c) | (b0 & d) | (c & d) : b0 ^ c ^ d, k = i < 20 ? 0x5a827999 : i < 40 ? 0x6ed9eba1 : i < 60 ? 0x8f1bbcdc : 0xca62c1d6, t = ((((a << 5) | (a >>> 27)) + f + e + k + w[i]) & 0xffffffff) >>> 0; e = d; d = c; c = ((b0 << 30) | (b0 >>> 2)) >>> 0; b0 = a; a = t; }
    [this.h0, this.h1, this.h2, this.h3, this.h4] = [this.h0 + a, this.h1 + b0, this.h2 + c, this.h3 + d, this.h4 + e].map(x => x >>> 0); }
  update(d) {
    if (!d?.length) return this;
    let i = 0; this.bytes += d.length;
    if (this.bufLen) { const n = Math.min(64 - this.bufLen, d.length); this.buf.set(d.subarray(0, n), this.bufLen); this.bufLen += n; i = n; this.bufLen === 64 && (this._blk(this.buf), this.bufLen = 0); }
    for (; i + 64 <= d.length; i += 64) this._blk(d, i);
    return i < d.length && (this.buf.set(d.subarray(i), 0), this.bufLen = d.length - i), this; }
  digest() {
    const s = this.clone(), len = s.bytes, dv = new DataView(s.buf.buffer);
    s.buf[s.bufLen++] = 0x80; s.bufLen > 56 && (s.buf.fill(0, s.bufLen, 64), s._blk(s.buf), s.bufLen = 0); s.buf.fill(0, s.bufLen, 56); dv.setUint32(56, Math.floor(len / 0x20000000)); dv.setUint32(60, (len << 3) >>> 0); s._blk(s.buf);
    const out = new Uint8Array(20), od = new DataView(out.buffer); [s.h0, s.h1, s.h2, s.h3, s.h4].forEach((x, i) => od.setUint32(i * 4, x)); return out; } }
class AesCtr {
  constructor(key) { Object.assign(this, { key, off: 0, ck: null, ctr: new Uint8Array(16), dv: null, scratch: new Uint8Array(16 + CELL) }); }
  async init() { this.ck = await cry.importKey('raw', this.key, 'AES-CTR', 0, ['encrypt']); this.dv = new DataView(this.ctr.buffer); }
  async process(d) {
    const n = d.length, bOff = this.off & 15; this.dv.setUint32(12, Math.floor(this.off / 16));
    let inp = d;
    if (bOff) { const end = bOff + n; this.scratch.length < end && (this.scratch = new Uint8Array(end)); this.scratch.fill(0, 0, bOff); this.scratch.set(d, bOff); inp = this.scratch.subarray(0, end); }
    const out = new Uint8Array(await cry.encrypt({ name: 'AES-CTR', counter: this.ctr, length: 128 }, this.ck, inp));
    return this.off += n, bOff ? out.subarray(bOff, bOff + n) : out; } }
const CELL = 514, CIRC = 0x80000001, Z4 = new Uint8Array(4);
const CMD = { RELAY: 3, DESTROY: 4, VER: 7, NET: 8, EARLY: 9, CREATE2: 10, CREATED2: 11 }, REL = { BEGIN: 1, DATA: 2, END: 3, CONN: 4, EXT2: 14, EXT2D: 15 };
const NTOR = Object.fromEntries(['ID', 'MAC', 'KEY', 'VER', 'EXP'].map((k, i) => [k, en(`ntor-curve25519-sha256-1${['', ':mac', ':key_extract', ':verify', ':key_expand'][i]}`)])), SERVER = en('Server');
const mkCell = (cid, cmd, p = u8()) => { const c = new Uint8Array(CELL); return new DataView(c.buffer).setUint32(0, cid), c[4] = cmd, c.set(p.slice(0, 509), 5), c; };
const mkRelay = (cmd, sid, d = u8()) => { const p = new Uint8Array(509); return p[0] = cmd, [p[3], p[4]] = u16(sid), [p[9], p[10]] = u16(d.length), d.length && p.set(d.slice(0, 498), 11), p; };
const rdRelay = d => ({ cmd: d[0], data: d.slice(11, 11 + (d[9] << 8 | d[10])) });
class TorCircuit {
  constructor(tls) { Object.assign(this, { tls, hops: [], q: [], qi: 0, qOff: 0, qBytes: 0, early: 0, xk: new Map() }); }
  _take(n) {
    const out = new Uint8Array(n); let o = 0;
    while (o < n) { const h = this.q[this.qi], m = Math.min(n - o, h.length - this.qOff); out.set(h.subarray(this.qOff, this.qOff + m), o); o += m; this.qOff += m; this.qBytes -= m; this.qOff === h.length && (++this.qi === this.q.length ? (this.q = [], this.qi = 0) : 0, this.qOff = 0); }
    return out; }
  async read() { while (this.qBytes < CELL) { const d = await this.tls.read(); if (!d?.length) return null; this.q.push(d); this.qBytes += d.length; } return this._take(CELL); }
  async _keys(kp, cpub, spub, nid, npub) {
    const getKey = async raw => this.xk.get(u8hex(raw)) ?? (this.xk.set(u8hex(raw), cry.importKey('raw', raw, 'X25519', 0, [])), this.xk.get(u8hex(raw)));
    const [xy, xb] = (await Promise.all([spub, npub].map(async raw => cry.deriveBits({ name: 'X25519', public: await getKey(raw) }, kp.privateKey, 256)))).map(ab => new Uint8Array(ab));
    const [v, seed] = await Promise.all([hmaci('VER', cat(xy, xb, nid, npub, cpub, spub, NTOR.ID)), hmaci('KEY', cat(xy, xb, nid, npub, cpub, spub, NTOR.ID))]);
    const auth = await hmaci('MAC', cat(v, nid, npub, spub, cpub, NTOR.ID, SERVER)), out = new Uint8Array(128);
    let prev = u8();
    for (let i = 0, p = 0; i < 4; i++, p += 32) prev = await hmac256(seed, cat(prev, NTOR.EXP, [i + 1])), out.set(prev, p);
    return { auth, Df: out.subarray(0, 20), Db: out.subarray(20, 40), Kf: out.subarray(40, 56), Kb: out.subarray(56, 72) }; }
  async _hop({ Df, Db, Kf, Kb }) { const [fwd, bwd] = [new AesCtr(Kf), new AesCtr(Kb)]; await Promise.all([fwd, bwd].map(c => c.init())); this.hops.push({ fwd, bwd, fb: new Sha1(Df), bb: new Sha1(Db) }); }
  async _hs(nid, npub, ext, a, p) {
    const kp = await cry.generateKey('X25519', 1, ['deriveBits']), cpub = new Uint8Array(await cry.exportKey('raw', kp.publicKey)), hd = cat(nid, npub, cpub);
    let sp, ad;
    if (ext) { await this.send(REL.EXT2, 0, cat([2, 0, 6], a.split('.').map(Number), u16(p), [2, 20], nid, [0, 2, 0, 84], hd), 1); const r = await this.recv(); if (r?.cmd !== REL.EXT2D) throw new Error('EXT2'); sp = r.data.slice(2, 34); ad = r.data.slice(34, 66); }
    else { await this.tls.write(mkCell(CIRC, CMD.CREATE2, cat([0, 2], u16(hd.length), hd))); const r = await this.read(); if (r?.[4] !== CMD.CREATED2) throw new Error('CREATE2'); sp = r.slice(7, 39); ad = r.slice(39, 71); }
    const { auth, ...keys } = await this._keys(kp, cpub, sp, nid, npub); if (!ad.every((b, i) => b === auth[i])) throw new Error('auth'); await this._hop(keys); }
  create = (nid, npub) => this._hs(nid, npub, 0);
  extend = (nid, npub, a, p) => this._hs(nid, npub, 1, a, p);
  async send(cmd, sid, d = u8(), early = 0) {
    const p = mkRelay(cmd, sid, d), h = this.hops.at(-1), hash = (h.fb.update(p), h.fb.digest()); [p[5], p[6], p[7], p[8]] = hash;
    let enc = p; for (let i = this.hops.length - 1; i >= 0; i--) enc = await this.hops[i].fwd.process(enc);
    await this.tls.write(mkCell(CIRC, early && this.early < 8 ? (this.early++, CMD.EARLY) : CMD.RELAY, enc)); }
  async recv() {
    const r = await this.read(); if (!r || r[4] !== CMD.RELAY) return null;
    let decd = r.slice(5);
    for (const h of this.hops) {
      decd = await h.bwd.process(decd);
      if (!(decd[1] << 8 | decd[2])) { const nx = h.bb.clone(), got = decd.subarray(5, 9); nx.update(decd.subarray(0, 5)).update(Z4).update(decd.subarray(9)); const hash = nx.digest(); if ([0, 1, 2, 3].every(i => hash[i] === got[i])) { h.bb = nx; break; } } }
    return rdRelay(decd); }
  async begin(sid, host, port) { const pl = en(`${host}:${port}\0`), d = new Uint8Array(pl.length + 4); d.set(pl); new DataView(d.buffer).setUint32(pl.length, 1); await this.send(REL.BEGIN, sid, d); const r = await this.recv(); if (r?.cmd !== REL.CONN) throw new Error('BEGIN'); }
  async data(sid, d) { for (let i = 0; i < d.length; i += 498) await this.send(REL.DATA, sid, d.slice(i, i + 498)); } }
class TorStream {
  constructor(circ, sid) {
    this.closed = 0;
    this.readable = new ReadableStream({ pull: async ctl => { const r = !this.closed && await circ.recv().catch(() => null); r?.cmd === REL.DATA ? ctl.enqueue(r.data) : (this.closed = 1, ctl.close()); } });
    this.writable = new WritableStream({ write: d => this.closed ? Promise.reject(Error('closed')) : circ.data(sid, d), close: () => (this.closed = 1) }); } }
const AUTH = '128.31.0.39:9131,86.59.21.38:80,45.66.33.45:80,66.111.2.131:9030,131.188.40.189:80,193.23.244.244:80,171.25.193.9:443,199.58.81.140:80,204.13.164.118:80'.split(',').map(s => { const [h, p] = s.split(':'); return { h, p: +p }; });
const sget = async (h, p, path, t = 15000) => {
  const s = connect({ hostname: h, port: p }), tm = setTimeout(() => { try { s.close(); } catch {} }, t); let rd;
  try {
    await s.opened; const w = s.writable.getWriter(); await w.write(en(`GET ${path} HTTP/1.1\r\nHost: ${h}:${p}\r\nConnection: close\r\n\r\n`)); w.releaseLock();
    const chunks = []; rd = s.readable.getReader(); let total = 0;
    for (; total < 2e6;) { const { done, value } = await rd.read(); if (done) break; value?.length && (chunks.push(value), total += value.length); }
    const txt = de(cat(...chunks)), i = txt.indexOf('\r\n\r\n'); return i >= 0 ? txt.slice(i + 4) : txt;
  } finally { clearTimeout(tm); try { rd?.releaseLock(); } catch {} try { s.close(); } catch {} } };
let _con = null, _conAt = 0;
const fetchCon = async (now = Date.now()) => _con && now - _conAt < 300000 ? _con : (_con = await first(AUTH.map(({ h, p }) => () => sget(h, p, '/tor/status-vote/current/consensus', 30000))), _con && (_conAt = now), _con);
const parseRows = txt => txt.split('\nr ').slice(1).map(x => {
  const [rL, ...rest] = x.split('\n'), rm = rL.match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)/);
  const fl = (rest.find(l => l[0] === 's')?.slice(2) ?? '').split(' '), bw = +(rest.find(l => l[0] === 'w')?.match(/Bandwidth=(\d+)/)?.[1] ?? 0);
  return rm && fl.includes('Valid') && fl.includes('Running') && { addr: rm[1], port: +rm[2], bw, fl };
}).filter(Boolean);
const getServ = async req => {
  try {
    const hops = Math.min(8, Math.max(1, +(new URL(req.url).searchParams.get('hops') ?? 3))), txt = await fetchCon(); if (!txt) return new Response('no consensus', { status: 502 });
    const top = (a, n) => a.sort((x, y) => y.bw - x.bw).slice(0, n), rows = parseRows(txt);
    const [gs, ms, es] = [top(rows.filter(n => n.fl.includes('Guard') && n.fl.includes('Stable')), 200), top(rows.filter(n => n.fl.includes('Stable') && !n.fl.includes('Exit')), 300), top(rows.filter(n => n.fl.includes('Exit') && !n.fl.includes('BadExit')), 500)];
    if (!gs.length || !es.length) return new Response('empty directory', { status: 502 });
    const used = new Set(), key = n => `${n.addr}:${n.port}`, pk = a => Array.from({ length: 20 }, () => pick(a)).find(n => n && !used.has(key(n)) && (used.add(key(n)), 1));
    const path = hops === 1 ? [pk(es)].filter(Boolean) : [pk(gs), ...Array.from({ length: Math.max(0, hops - 2) }, () => pk(ms)), pk(es)].filter(Boolean);
    return path.length === hops ? new Response(`/tor://[${path.map(n => `${n.addr}:${n.port}`).join('→')}]`) : new Response('no path', { status: 502 });
  } catch (e) { return new Response(e.message, { status: 500 }); } };
const getTor = url => { const path = decodeURIComponent(url).match(/\/tor:\/\/\[([^\]]+)]/i)?.[1]?.split(/→|->/).map(s => { const [addr, port] = s.trim().split(':'); return addr && port ? { addr, port: +port } : null; }).filter(Boolean); return path?.length >= 1 && path.length <= 8 ? path : null; };
const _resolved = new Map(), _ntor = new Map();
const loadNtor = fp => _ntor.get(fp) ?? first(AUTH.map(({ h, p }) => async () => (await sget(h, p, `/tor/server/fp/${fp}`, 10000)).match(/ntor-onion-key ([A-Za-z0-9+/=]+)/)?.[1])).then(s => s && (_ntor.set(fp, b64d(s)), _ntor.get(fp)));
const resolve = async nodes => {
  const key = nodes.map(n => `${n.addr}:${n.port}`).join('|'); if (_resolved.has(key)) return _resolved.get(key);
  const txt = await fetchCon(); if (!txt) return null;
  const res = nodes.map(({ addr, port }) => { const m = txt.match(new RegExp(`^r \\S+ (\\S+) \\S+ \\S+ \\S+ ${esc(addr)} ${port}\\b`, 'm')); return m && { addr, port, fp: u8hex(b64d(m[1])), nid: b64d(m[1]), ntor: null }; });
  return res.every(Boolean) && await Promise.all(res.map(async n => (n.ntor = await loadNtor(n.fp)))) && res.every(n => n.ntor) ? (_resolved.set(key, res), res) : null; };
const link = async tls => (await tls.write(u8(0, 0, CMD.VER, 0, 6, 0, 3, 0, 4, 0, 5)), await tls.read(), tls.write(mkCell(0, CMD.NET, u8(u32(Date.now() / 1000 | 0), 4, 4, 0, 0, 0, 0, 0))));
const torConn = async (nodes, host, port) => {
  const path = await resolve(nodes); if (!path) return null;
  const s = connect({ hostname: path[0].addr, port: path[0].port }); await s.opened;
  const tls = new TlsClient(s, { serverName: path[0].addr, insecure: 1 }); await tls.handshake(); await link(tls);
  const c = new TorCircuit(tls); await c.create(path[0].nid, path[0].ntor); await path.slice(1).reduce((p, n) => p.then(() => c.extend(n.nid, n.ntor, n.addr, n.port)), Promise.resolve()); await c.begin(1, host, port);
  const ts = new TorStream(c, 1); return { readable: ts.readable, writable: ts.writable, close: () => { try { s.close(); } catch {} } }; };
const ws = async req => {
  const [client, server] = Object.values(new WebSocketPair()); server.accept();
  const ed = req.headers.get('sec-websocket-protocol'), tor = getTor(req.url); let w = null, sock = null, chain = Promise.resolve();
  const close = () => { try { sock?.close(); } catch {} try { server.close(); } catch {} }, send = d => { try { server.send(d); } catch {} };
  const process = async chunk => {
    if (w) return w.write(chunk);
    const v = vless(chunk); if (!v || !tor) return close(); send(new Uint8Array([chunk[0], 0]));
    const { addrType, addrBytes, dataOffset, port } = v, host = addr(addrType, addrBytes), payload = chunk.subarray(dataOffset);
    if (!(sock = await torConn(tor, host, port).catch(() => null))) return close();
    w = sock.writable.getWriter(); payload.byteLength && await w.write(payload); relay(sock.readable.getReader(), send, close); };
  ed?.length <= maxED && (chain = chain.then(() => process(b64u8(ed, 1))).catch(close));
  server.addEventListener('message', e => { chain = chain.then(() => process(toU8(e.data))).catch(close); });
  server.addEventListener('close', close); server.addEventListener('error', close);
  return new Response(null, { status: 101, webSocket: client, headers: ed ? { 'sec-websocket-protocol': ed } : {} }); };
export default { fetch: req => req.headers.get('Upgrade') === 'websocket' ? ws(req) : new URL(req.url).pathname === '/getServ' ? getServ(req) : new Response('ok') };