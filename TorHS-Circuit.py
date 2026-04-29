import asyncio, aiohttp, ssl, struct, time, hashlib, hmac, re, base64, sys, random, os, bisect, json
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
from enum import IntEnum
from python_socks.async_.asyncio.v2 import Proxy
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from hashlib import sha3_256, shake_256
# ==================== Constants ====================
CELL_LEN = 514
CMD = {'RELAY': 3, 'DESTROY': 4, 'NETINFO': 8, 'RELAY_EARLY': 9, 'CREATE2': 10, 'CREATED2': 11}
RELAY = {
    'BEGIN': 1, 'DATA': 2, 'END': 3, 'CONNECTED': 4, 'EXTEND2': 14, 'EXTENDED2': 15,
    'BEGIN_DIR': 13, 'ESTABLISH_INTRO': 32, 'INTRO_ESTABLISHED': 38,
    'INTRODUCE1': 34, 'INTRODUCE_ACK': 40, 'ESTABLISH_RENDEZVOUS': 33,
    'RENDEZVOUS_ESTABLISHED': 39, 'RENDEZVOUS2': 37,
}
NTOR = {k: f'ntor-curve25519-sha256-1:{v}'.encode() if v else b'ntor-curve25519-sha256-1'
        for k, v in [('ID', ''), ('MAC', 'mac'), ('KEY', 'key_extract'), ('VERIFY', 'verify'), ('EXPAND', 'key_expand')]}
DIR_AUTHS = [('128.31.0.39', 9131), ('86.59.21.38', 80), ('45.66.33.45', 80), ('66.111.2.131', 9030),
             ('131.188.40.189', 80), ('193.23.244.244', 80), ('171.25.193.9', 443), ('199.58.81.140', 80)]
ONIONOO = 'https://onionoo.torproject.org/details'
PROTOID = b'tor-hs-ntor-curve25519-sha3-256-1'
ED_Q, ED_L = 2**255 - 19, 2**252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, ED_Q - 2, ED_Q) % ED_Q
ED_I = pow(2, (ED_Q - 1) // 4, ED_Q)
ED_BASEPOINT_STR = b'(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)'
CACHE_PATH = '/tmp/tor_cache.json'
HS_DESC_CACHE_PATH = '/tmp/tor_hs_desc_cache.json'
# ==================== Ed25519 Pure Python ====================
def _ed_inv(z): return pow(z, ED_Q - 2, ED_Q)
def _ed_xrecover(y):
    xx = (y * y - 1) * _ed_inv(ED_D * y * y + 1) % ED_Q
    x = pow(xx, (ED_Q + 3) // 8, ED_Q)
    return ED_Q - x if (x * x - xx) % ED_Q and (x := x * ED_I % ED_Q) or x & 1 else x
ED_BY = 4 * _ed_inv(5) % ED_Q
ED_BX = _ed_xrecover(ED_BY)
ED_B = (ED_BX % ED_Q, ED_BY % ED_Q, 1, ED_BX * ED_BY % ED_Q)
def _ed_add(P, Q):
    x1, y1, z1, t1, x2, y2, z2, t2 = *P, *Q
    a, b = (y1 - x1) * (y2 - x2) % ED_Q, (y1 + x1) * (y2 + x2) % ED_Q
    c, dd = t1 * 2 * ED_D * t2 % ED_Q, z1 * 2 * z2 % ED_Q
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % ED_Q, g * h % ED_Q, f * g % ED_Q, e * h % ED_Q)
def _ed_double(P):
    x1, y1, z1, _ = P
    a, b, c = x1 * x1 % ED_Q, y1 * y1 % ED_Q, 2 * z1 * z1 % ED_Q
    e = ((x1 + y1)**2 - a - b) % ED_Q
    g, f, h = -a + b, -a + b - c, -a - b
    return (e * f % ED_Q, g * h % ED_Q, f * g % ED_Q, e * h % ED_Q)
def _ed_scalarmult(P, e):
    R = (0, 1, 1, 0)
    while e:
        R, P, e = (_ed_add(R, P), _ed_double(P), e >> 1) if e & 1 else (R, _ed_double(P), e >> 1)
    return R
def _ed_encodepoint(P):
    x, y = (v := P[0] * (zi := _ed_inv(P[2])) % ED_Q), P[1] * zi % ED_Q
    return (y | ((v & 1) << 255)).to_bytes(32, 'little')
def _ed_decodepoint(s):
    y, x = int.from_bytes(s, 'little') & ((1 << 255) - 1), _ed_xrecover(int.from_bytes(s, 'little') & ((1 << 255) - 1))
    return (ED_Q - x if x & 1 != s[31] >> 7 else x, y, 1, (ED_Q - x if x & 1 != s[31] >> 7 else x) * y % ED_Q)
def ed25519_blind(pubkey, param):
    k = bytearray(param); k[0] &= 248; k[31] = (k[31] & 63) | 64
    return _ed_encodepoint(_ed_scalarmult(_ed_decodepoint(pubkey), int.from_bytes(k, 'little')))

def ed25519_verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    """验证 Ed25519 签名 (纯 Python 实现)"""
    if len(pubkey) != 32 or len(sig) != 64: return False
    try:
        R = _ed_decodepoint(sig[:32])
        A = _ed_decodepoint(pubkey)
        s = int.from_bytes(sig[32:], 'little')
        if s >= ED_L: return False
        h = int.from_bytes(hashlib.sha512(sig[:32] + pubkey + msg).digest(), 'little') % ED_L
        sB = _ed_scalarmult(ED_B, s)
        hA = _ed_scalarmult(A, h)
        RhA = _ed_add(R, hA)
        return _ed_encodepoint(sB) == _ed_encodepoint(RhA)
    except: return False

def verify_hs_descriptor(raw: bytes, blinded_pubkey: bytes) -> Tuple[bool, str]:
    """
    验证 HS 描述符签名
    返回: (is_valid, error_message)
    """
    txt = raw.decode('latin1', errors='replace')

    # 1. 解析 signing-key-cert
    if 'signing-key-cert' not in txt:
        return False, 'Missing signing-key-cert'

    cert_start = txt.find('-----BEGIN ED25519 CERT-----')
    cert_end = txt.find('-----END ED25519 CERT-----')
    if cert_start < 0 or cert_end < 0:
        return False, 'Invalid signing-key-cert format'

    cert_b64 = txt[cert_start+28:cert_end].replace('\n', '').strip()
    try: cert = b64d(cert_b64)
    except: return False, 'Failed to decode cert'

    if len(cert) < 104: return False, f'Cert too short: {len(cert)}'

    # 解析证书结构
    # Version(1) + Type(1) + Expiry(4) + KeyType(1) + CertifiedKey(32) + N_Extensions(1) + Extensions(...) + Signature(64)
    cert_type, expiry_hours = cert[1], struct.unpack('>I', cert[2:6])[0]
    certified_key = cert[7:39]

    # 检查证书类型 (08 = signing key)
    if cert_type != 0x08:
        return False, f'Invalid cert type: {cert_type}'

    # 检查过期时间 (hours since epoch)
    expiry_ts = expiry_hours * 3600
    if time.time() > expiry_ts:
        return False, f'Cert expired at {expiry_ts}'

    # 2. 验证证书签名 (签名在最后64字节)
    cert_sig = cert[-64:]
    cert_body = cert[:-64]
    if not ed25519_verify(blinded_pubkey, cert_body, cert_sig):
        return False, 'Cert signature verification failed'

    # 3. 解析并验证 descriptor signature
    sig_marker = 'signature '
    sig_pos = txt.find(sig_marker)
    if sig_pos < 0:
        return False, 'Missing descriptor signature'

    sig_line_end = txt.find('\n', sig_pos)
    sig_b64 = txt[sig_pos + len(sig_marker):sig_line_end].strip()
    try: desc_sig = b64d(sig_b64)
    except: return False, 'Failed to decode descriptor signature'

    if len(desc_sig) != 64:
        return False, f'Invalid signature length: {len(desc_sig)}'

    # 4. 计算要签名的内容 (从开头到 "signature " 之前)
    signed_content = txt[:sig_pos].encode('latin1')
    # Tor 官方 ed25519_checksig_prefixed() 直接拼接 prefix + descriptor content。
    # 参考 tor-main/src/feature/hs/hs_descriptor.c:desc_sig_is_valid。
    signed_data = b'Tor onion service descriptor sig v3' + signed_content

    if not ed25519_verify(certified_key, signed_data, desc_sig):
        return False, 'Descriptor signature verification failed'

    return True, 'OK'
# ==================== Utils ====================
hmac256 = lambda k, m: hmac.new(k, m, hashlib.sha256).digest()
b64d = lambda s: base64.b64decode(s.replace('-', '+').replace('_', '/') + '=' * (-len(s) % 4))
b32d = lambda s: base64.b32decode(s.upper() + '=' * (-len(s) % 8))
cell = lambda cid, cmd, p=b'': struct.pack('>IB', cid, cmd) + p.ljust(509, b'\x00')
mac_sha3 = lambda k, m: sha3_256(struct.pack('>Q', len(k)) + k + m).digest()
get_time_period = lambda ts=None: ((ts or int(time.time())) // 60 - 720) // 1440
async def read_limited(read, limit=1_000_000, timeout=20, chunk_size=65536):
    out = bytearray()
    while len(out) < limit:
        chunk = await asyncio.wait_for(read(min(chunk_size, limit - len(out))), timeout=timeout)
        if not chunk: break
        out.extend(chunk)
    return bytes(out)

def decode_chunked(body):
    out, i = bytearray(), 0
    while i < len(body) and (end := body.find(b'\r\n', i)) >= 0:
        try: size = int(body[i:end].split(b';', 1)[0], 16)
        except: break
        if size == 0: break
        out.extend(body[end+2:end+2+size]); i = end + 4 + size
    return bytes(out)
def parse_http(raw):
    if b'\r\n\r\n' not in raw: return raw
    hdr, body = raw.split(b'\r\n\r\n', 1)
    return hdr + b'\r\n\r\n' + (decode_chunked(body) if b'transfer-encoding: chunked' in hdr.lower() else body)
def relay_payload(cmd, sid, digest, data=b''):
    p = bytearray(509)
    p[0], p[11:11+len(data)] = cmd, data[:498]
    struct.pack_into('>HI', p, 3, sid, digest)
    struct.pack_into('>H', p, 9, len(data))
    return bytes(p)
def blind_pubkey(pubkey, period):
    nonce = b'key-blind' + struct.pack('>QQ', period, 1440)
    return ed25519_blind(pubkey, sha3_256(b'Derive temporary signing key\x00' + pubkey + ED_BASEPOINT_STR + nonce).digest())
hs_subcredential = lambda pk, bl: sha3_256(b'subcredential' + sha3_256(b'credential' + pk).digest() + bl).digest()
hs_desc_id = lambda bl, r, p: sha3_256(b'store-at-idx' + bl + struct.pack('>QQQ', r, 1440, p)).digest()
hsdir_index = lambda nid, srv, p: sha3_256(b'node-idx' + nid + srv + struct.pack('>QQ', p, 1440)).digest()
def hs_desc_decrypt(ciphertext, blinded, subcred, rev_counter, expand_const):
    if len(ciphertext) < 48: return None
    salt, enc, mac = ciphertext[:16], ciphertext[16:-32], ciphertext[-32:]
    keys = shake_256(blinded + subcred + struct.pack('>Q', rev_counter) + salt + expand_const).digest(80)
    if mac != mac_sha3(keys[48:], struct.pack('>Q', 16) + salt + enc): return None
    return Cipher(algorithms.AES(keys[:32]), modes.CTR(keys[32:48]), default_backend()).decryptor().update(enc)
def parse_onion_v3(addr):
    addr, data = addr.lower().replace('.onion', '').strip(), b32d(addr.lower().replace('.onion', '').strip())
    if len(addr) != 56: raise ValueError(f'Invalid length: {len(addr)}')
    if data[34] != 3: raise ValueError(f'Unsupported version: {data[34]}')
    if data[32:34] != sha3_256(b'.onion checksum' + data[:32] + bytes([3])).digest()[:2]:
        raise ValueError('Checksum mismatch')
    return data[:32], 3
def ntor_derive(kp, cpub, spub, node_id, node_key):
    xy, xb = kp.exchange(X25519PublicKey.from_public_bytes(spub)), kp.exchange(X25519PublicKey.from_public_bytes(node_key))
    secret = xy + xb + node_id + node_key + cpub + spub + NTOR['ID']
    verify = hmac256(NTOR['VERIFY'], secret)
    auth = hmac256(NTOR['MAC'], verify + node_id + node_key + spub + cpub + NTOR['ID'] + b'Server')
    seed, mat, prev = hmac256(NTOR['KEY'], secret), b'', b''
    for i in range(1, 6): prev = hmac256(seed, prev + NTOR['EXPAND'] + bytes([i])); mat += prev
    return auth, mat[:20], mat[20:40], mat[40:56], mat[56:72]
# ==================== Data Classes ====================
class IptOutcome(IntEnum):
    SUCCESS = 0      # 成功 (最优先)
    UNTRIED = 1      # 未尝试 (次优先)
    FAILED = 2       # 失败 (最低优先)

@dataclass
class IptExperience:
    """记录单个 Intro Point 的使用经验"""
    outcome: IptOutcome = IptOutcome.UNTRIED
    duration: float = 0.0           # 耗时 (秒)
    last_attempt: float = 0.0       # 最后尝试时间戳
    fail_count: int = 0             # 连续失败次数
    retry_after: float = 0.0        # 下次重试时间戳

    def sort_key(self) -> Tuple[int, float, float]:
        """排序键: (outcome, duration, -last_attempt) - 越小越优先"""
        return (self.outcome, self.duration if self.outcome == IptOutcome.SUCCESS else 999, -self.last_attempt)

    def record_success(self, duration: float):
        self.outcome, self.duration, self.last_attempt, self.fail_count = IptOutcome.SUCCESS, duration, time.time(), 0

    def record_failure(self, duration: float):
        self.fail_count += 1
        self.outcome, self.duration, self.last_attempt = IptOutcome.FAILED, duration, time.time()
        self.retry_after = time.time() + min(30 * (2 ** self.fail_count), 600)  # 指数退避, 最大10分钟

class TimeoutEstimator:
    """动态超时估算器 - 基于历史 RTT 统计"""
    def __init__(self):
        self.rtt_samples: Dict[int, list] = {}  # hops -> [rtt_samples]
        self.build_samples: Dict[int, list] = {}  # hops -> [build_time_samples]
        self.max_samples = 50

    def record_rtt(self, hops: int, rtt: float):
        """记录一次 RTT"""
        if hops not in self.rtt_samples: self.rtt_samples[hops] = []
        self.rtt_samples[hops].append(rtt)
        if len(self.rtt_samples[hops]) > self.max_samples:
            self.rtt_samples[hops] = self.rtt_samples[hops][-self.max_samples:]

    def record_build(self, hops: int, duration: float):
        """记录一次电路建立时间"""
        if hops not in self.build_samples: self.build_samples[hops] = []
        self.build_samples[hops].append(duration)
        if len(self.build_samples[hops]) > self.max_samples:
            self.build_samples[hops] = self.build_samples[hops][-self.max_samples:]

    def _percentile(self, samples: list, p: float) -> float:
        """计算百分位数"""
        if not samples: return 0
        sorted_s = sorted(samples)
        idx = int(len(sorted_s) * p / 100)
        return sorted_s[min(idx, len(sorted_s) - 1)]

    def estimate_rtt(self, hops: int, default: float = 5.0) -> float:
        """估算 RTT (使用 90 百分位)"""
        samples = self.rtt_samples.get(hops, [])
        if len(samples) < 3: return default * hops  # 默认每跳 5 秒
        return max(self._percentile(samples, 90), 1.0)

    def estimate_build(self, hops: int, default: float = 10.0) -> float:
        """估算电路建立时间 (使用 90 百分位)"""
        samples = self.build_samples.get(hops, [])
        if len(samples) < 3: return default * hops  # 默认每跳 10 秒
        return max(self._percentile(samples, 90), 2.0)

    def timeout(self, hops: int, action: str = 'rtt', multiplier: float = 1.5) -> float:
        """获取超时时间"""
        if action == 'build':
            base = self.estimate_build(hops)
        else:
            base = self.estimate_rtt(hops)
        return min(max(base * multiplier, 5.0), 120.0)  # 最小5秒, 最大120秒

# 全局超时估算器
TIMEOUT = TimeoutEstimator()

@dataclass
class Node:
    name: str; addr: str; port: int; fp: str; id: bytes
    flags: list = field(default_factory=list)
    ntor: bytes = None; ed25519: bytes = None; ed25519_id: bytes = None
    microdesc: str = None; hsdir_idx: bytes = None
    def to_dict(self): return {'name': self.name, 'addr': self.addr, 'port': self.port, 'fp': self.fp, 'flags': self.flags}
    @classmethod
    def from_dict(cls, d): return cls(d['name'], d['addr'], d['port'], d['fp'], bytes.fromhex(d['fp']), d.get('flags', []))
# ==================== TorCircuit ====================
class TorCircuit:
    def __init__(self, reader, writer, circ_id):
        self.reader, self.writer, self.circ_id = reader, writer, circ_id
        self.hops, self.buf, self.early_cnt = [], b'', 0
    async def _read(self, timeout=30):
        try:
            while len(self.buf) < CELL_LEN:
                if not (d := await asyncio.wait_for(self.reader.read(4096), timeout=timeout)): return None
                self.buf += d
            c, self.buf = self.buf[:CELL_LEN], self.buf[CELL_LEN:]
            return c
        except: return None
    def _add_hop(self, Df, Db, Kf, Kb, is_hs=False):
        hash_fn = sha3_256 if is_hs else hashlib.sha1
        self.hops.append({
            'fd': hash_fn(Df), 'bd': hash_fn(Db),
            'fc': Cipher(algorithms.AES(Kf), modes.CTR(b'\x00' * 16), default_backend()).encryptor(),
            'bc': Cipher(algorithms.AES(Kb), modes.CTR(b'\x00' * 16), default_backend()).decryptor(),
        })
    async def _send(self, cmd, sid, data=b'', early=False):
        hop, p0 = self.hops[-1], relay_payload(cmd, sid, 0, data)
        dc = hop['fd'].copy(); dc.update(p0)
        hop['fd'].update(p0)
        enc = relay_payload(cmd, sid, struct.unpack('>I', dc.digest()[:4])[0], data)
        for h in reversed(self.hops): enc = h['fc'].update(enc)
        c = CMD['RELAY_EARLY'] if early and self.early_cnt < 8 else CMD['RELAY']
        if c == CMD['RELAY_EARLY']: self.early_cnt += 1
        self.writer.write(cell(self.circ_id, c, enc)); await self.writer.drain()
    async def _recv(self, max_pad=200, timeout=30):
        recv_start = time.time()
        if not (r := await self._read(timeout)): return None
        cmd = r[4]
        if cmd == CMD['DESTROY']: raise Exception(f'DESTROY: reason={r[5]}')
        if cmd == 0: return await self._recv(max_pad - 1, timeout) if max_pad > 0 else None
        if cmd != CMD['RELAY']: raise Exception(f'Unexpected cmd: {cmd}')
        dec = r[5:514]
        for h in self.hops:
            dec = h['bc'].update(dec)
            if dec[1:3] == b'\x00\x00': break
        dlen = (dec[9] << 8) | dec[10]
        # 记录 RTT
        TIMEOUT.record_rtt(len(self.hops), time.time() - recv_start)
        return {'cmd': dec[0], 'sid': (dec[3] << 8) | dec[4], 'data': dec[11:11+dlen]}
    async def create(self, node_id, node_key):
        kp, cpub = X25519PrivateKey.generate(), None
        cpub = kp.public_key().public_bytes_raw()
        hdata = node_id + node_key + cpub
        self.writer.write(cell(self.circ_id, CMD['CREATE2'], struct.pack('>HH', 2, len(hdata)) + hdata))
        await self.writer.drain()
        if not (r := await self._read()) or r[4] != CMD['CREATED2']:
            raise Exception(f'CREATE2 failed: {r[4] if r else None}')
        auth, Df, Db, Kf, Kb = ntor_derive(kp, cpub, r[7:39], node_id, node_key)
        if auth != r[39:71]: raise Exception('ntor auth mismatch')
        self._add_hop(Df, Db, Kf, Kb)
    async def extend(self, node_id, node_key, addr, port, ed_key=None):
        kp, cpub = X25519PrivateKey.generate(), None
        cpub = kp.public_key().public_bytes_raw()
        ip = bytes(int(x) for x in addr.split('.'))
        specs = bytes([0, 6]) + ip + struct.pack('>H', port) + bytes([2, 20]) + node_id
        if ed_key and len(ed_key) == 32: specs += bytes([3, 32]) + ed_key
        hdata = node_id + node_key + cpub
        await self._send(RELAY['EXTEND2'], 0, bytes([3 if ed_key and len(ed_key) == 32 else 2]) + specs + struct.pack('>HH', 2, len(hdata)) + hdata, True)
        if not (r := await self._recv()) or r['cmd'] != RELAY['EXTENDED2']:
            raise Exception(f'EXTEND2 failed: {r}')
        auth, Df, Db, Kf, Kb = ntor_derive(kp, cpub, r['data'][2:34], node_id, node_key)
        if auth != r['data'][34:66]: raise Exception('EXTEND2 auth mismatch')
        self._add_hop(Df, Db, Kf, Kb)
    async def send(self, cmd, sid, data=b''): await self._send(cmd, sid, data)
    async def recv(self, timeout=30): return await self._recv(timeout=timeout)
    def close(self):
        try: self.writer.close()
        except: pass
# ==================== TorDirectory ====================
class TorDirectory:
    def __init__(self, proxy=('127.0.0.1', 2080)):
        self.proxy = proxy
        self.guards, self.middles, self.exits = [], [], []
        self.desc_cache, self.srv, self.srv_prev, self.hsdirs, self.hsdir_rings, self.consensus = {}, None, None, [], {}, None
        self._load_cache()
    def _load_cache(self):
        try:
            with open(CACHE_PATH) as f: d = json.load(f)
            age = time.time() - d.get('timestamp', 0)
            if age < 86400:
                self.srv = bytes.fromhex(d['srv_current']) if d.get('srv_current') else None
                self.srv_prev = bytes.fromhex(d['srv_previous']) if d.get('srv_previous') else None
                self.hsdirs = [Node(h['name'], h['addr'], h['port'], h['fp'], bytes.fromhex(h['fp']), ed25519_id=bytes.fromhex(h['ed25519_id'])) for h in d.get('hsdirs', []) if h.get('ed25519_id')]
                self.hsdirs and print(f'  Loaded {len(self.hsdirs)} HSDirs from cache')
            if age < 3600 and d.get('guards'):
                self.guards, self.middles, self.exits = [Node.from_dict(n) for n in d['guards']], [Node.from_dict(n) for n in d.get('middles', [])], [Node.from_dict(n) for n in d.get('exits', [])]
                print(f'  Loaded nodes from cache: Guard:{len(self.guards)} Middle:{len(self.middles)} Exit:{len(self.exits)}')
        except: pass
    def _save_cache(self):
        data = {'timestamp': time.time(), 'guards': [n.to_dict() for n in self.guards], 'middles': [n.to_dict() for n in self.middles], 'exits': [n.to_dict() for n in self.exits]}
        if self.srv: data['srv_current'] = self.srv.hex()
        if self.srv_prev: data['srv_previous'] = self.srv_prev.hex()
        if self.hsdirs: data['hsdirs'] = [{'name': h.name, 'addr': h.addr, 'port': h.port, 'fp': h.fp, 'ed25519_id': h.ed25519_id.hex()} for h in self.hsdirs if h.ed25519_id]
        tmp = CACHE_PATH + '.tmp'
        with open(tmp, 'w') as f: json.dump(data, f)
        os.replace(tmp, CACHE_PATH)
    async def _http_get(self, host, port, path, timeout=15, limit=100000, mode='socks'):
        conn = None
        try:
            req = f'GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\n\r\n'.encode()
            try_socks = mode in ('socks', 'any')
            if try_socks:
                try: conn = await asyncio.wait_for(Proxy.from_url(f'socks5://{self.proxy[0]}:{self.proxy[1]}').connect(dest_host=host, dest_port=port), timeout=timeout)
                except:
                    if mode == 'socks': return None
                    conn = None
            if conn:
                await conn.write_all(req)
                data = await read_limited(conn.read, limit, timeout)
            else:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                writer.write(req); await writer.drain()
                data = await read_limited(reader.read, limit, timeout)
                conn = writer
            return data.decode('latin1', errors='replace')
        except: return None
        finally:
            try:
                r = conn.close()
                if asyncio.iscoroutine(r): await r
            except: pass
    async def _socks_get(self, host, port, path, timeout=15):
        return await self._http_get(host, port, path, timeout=timeout, limit=100000, mode='socks')
    async def _direct_get(self, host, port, path, timeout=15):
        return await self._http_get(host, port, path, timeout=timeout, limit=100000, mode='direct')
    async def fetch_consensus(self):
        print('  Fetching consensus (concurrent)...')
        async def fetch_one(host, port):
            txt = await self._http_get(host, port, '/tor/status-vote/current/consensus-microdesc', timeout=60, limit=5_000_000, mode='any')
            if not txt: return None
            idx = txt.find('\r\n\r\n')
            body = txt[idx+4:] if idx >= 0 else txt
            return (host, port, body) if len(body) > 100000 else None
        tasks = [asyncio.create_task(fetch_one(h, p)) for h, p in DIR_AUTHS]
        try:
            for coro in asyncio.as_completed(tasks):
                if result := await coro:
                    host, port, self.consensus = result
                    print(f'    {host}:{port} OK ({len(self.consensus)} bytes)')
                    return self.consensus
        finally:
            [t.cancel() for t in tasks if not t.done()]
        return None
    def parse_srv(self):
        if not self.consensus: return
        if m := re.search(r'shared-rand-current-value \d+ ([A-Za-z0-9+/=]+)', self.consensus):
            self.srv = base64.b64decode(m[1]); print(f'  SRV (current): {self.srv.hex()[:32]}...')
        if m := re.search(r'shared-rand-previous-value \d+ ([A-Za-z0-9+/=]+)', self.consensus):
            self.srv_prev = base64.b64decode(m[1]); print(f'  SRV (previous): {self.srv_prev.hex()[:32]}...')
        return self.srv
    async def _fetch_ed_keys_batch(self, digests, d2h, host, port):
        try:
            txt = await self._http_get(host, port, f'/tor/micro/d/{"-".join(digests)}', timeout=20, limit=2*1024*1024, mode='any')
            if not txt: return 0
            raw, count, pos = txt.encode('latin1', errors='replace'), 0, 0
            raw = raw[(idx + 4):] if (idx := raw.find(b'\r\n\r\n')) >= 0 else raw
            while (start := raw.find(b'onion-key\n', pos)) >= 0:
                end = raw.find(b'onion-key\n', start + 10)
                part, pos = (raw[start:end], end) if end > 0 else (raw[start:], len(raw))
                md_b64 = base64.b64encode(hashlib.sha256(part.rstrip(b'\n') + b'\n').digest()).decode().rstrip('=')
                if md_b64 in d2h and (ed_pos := part.find(b'id ed25519 ')) >= 0:
                    try:
                        eol = part.find(b'\n', ed_pos + 11)
                        d2h[md_b64].ed25519_id = b64d(part[ed_pos+11:eol if eol > 0 else len(part)].decode().strip())
                        count += 1
                    except: pass
            return count
        except: return 0
    async def build_hsdir_ring(self, period, srv=None):
        srv = srv or self.srv
        if not srv: return []
        key = (srv.hex(), period)
        if key in self.hsdir_rings: return self.hsdir_rings[key]
        if self.hsdirs and all(h.ed25519_id for h in self.hsdirs[:10]):
            ring = sorted([Node(h.name, h.addr, h.port, h.fp, h.id, ed25519_id=h.ed25519_id, hsdir_idx=hsdir_index(h.ed25519_id, srv, period)) for h in self.hsdirs], key=lambda x: x.hsdir_idx)
            self.hsdir_rings[key] = ring
            return ring
        if not self.consensus: return []
        print(f'  Building HSDir ring (period={period})...')
        hsdirs, txt, pos = [], self.consensus, 0
        while (r_pos := txt.find('\nr ', pos)) >= 0:
            r_pos += 1
            line_end = txt.find('\n', r_pos)
            if line_end < 0: break
            parts = txt[r_pos+2:line_end].split(' ')
            if len(parts) < 6: pos = line_end; continue
            nick, id_b64 = parts[0], parts[1]
            addr, port_str = next(((parts[i], parts[i+1]) for i in range(4, min(7, len(parts))) if '.' in parts[i] and parts[i].replace('.', '').isdigit() and i+1 < len(parts)), (None, None))
            if not addr: pos = line_end; continue
            try: port, rsa_id = int(port_str), b64d(id_b64)
            except: pos = line_end; continue
            block = txt[line_end:(next_r if (next_r := txt.find('\nr ', line_end)) > 0 else len(txt))]
            flags = block[s_pos+3:block.find('\n', s_pos+1) if block.find('\n', s_pos+1) >= 0 else len(block)].split() if (s_pos := block.find('\ns ')) >= 0 else []
            md = block[m_pos+3:block.find('\n', m_pos+1) if block.find('\n', m_pos+1) >= 0 else len(block)].split()[0] if (m_pos := block.find('\nm ')) >= 0 else None
            if all(f in flags for f in ['HSDir', 'Valid', 'Running']) and md:
                hsdirs.append(Node(nick, addr, port, rsa_id.hex().upper(), rsa_id, microdesc=md))
            pos = line_end
        print(f'    Found {len(hsdirs)} HSDirs, fetching ed25519 keys...')
        d2h = {h.microdesc: h for h in hsdirs}
        digests, batch_size = list(d2h.keys()), 80
        batches = [digests[i:i+batch_size] for i in range(0, len(digests), batch_size)]
        concurrent = min(len(batches), 50) or 1
        for i in range(0, len(batches), concurrent):
            if i == 0 or (i * batch_size) % 1000 < concurrent * batch_size:
                print(f'    Keys: {min(i*batch_size, len(digests))}/{len(digests)}...')
            await asyncio.gather(*[self._fetch_ed_keys_batch(b, d2h, *DIR_AUTHS[j % len(DIR_AUTHS)]) for j, b in enumerate(batches[i:i+concurrent], i)], return_exceptions=True)
        valid = sorted([Node(h.name, h.addr, h.port, h.fp, h.id, ed25519_id=h.ed25519_id, hsdir_idx=hsdir_index(h.ed25519_id, srv, period)) for h in hsdirs if h.ed25519_id], key=lambda x: x.hsdir_idx)
        self.hsdirs, self.hsdir_rings[key] = valid, valid
        self._save_cache()
        print(f'    Valid HSDirs: {len(valid)}')
        return valid
    async def get_responsible_hsdirs(self, blinded, period, srv=None):
        srv = srv or self.srv or (await self.fetch_consensus() or self.parse_srv() or None) and self.srv
        if not srv: return []
        ring = await self.build_hsdir_ring(period, srv)
        if not ring: return []
        indices, result = [h.hsdir_idx for h in ring], []
        for replica in range(1, 3):
            hs_idx = hs_desc_id(blinded, replica, period)
            print(f'    Replica {replica} hs_index: {hs_idx.hex()[:32]}...')
            pos = bisect.bisect_left(indices, hs_idx)
            for i in range(3):
                if (h := ring[(pos + i) % len(ring)]) not in result:
                    result.append(h); print(f'      -> {h.name} @ {h.addr}:{h.port}')
        return result
    async def get_descriptor(self, fp):
        if fp in self.desc_cache: return self.desc_cache[fp]
        async def fetch_one(host, port):
            txt = await self._socks_get(host, port, f'/tor/server/fp/{fp}')
            if not txt: return None
            r = {'single_hop': 'allow-single-hop-exits' in txt}
            if m := re.search(r'ntor-onion-key ([A-Za-z0-9+/=_-]+)', txt): r['ntor'] = b64d(m[1])
            if m := re.search(r'master-key-ed25519 ([A-Za-z0-9+/=_-]+)', txt): r['ed25519'] = b64d(m[1])
            return r if 'ntor' in r else None
        tasks = [asyncio.create_task(fetch_one(h, p)) for h, p in DIR_AUTHS[:4]]
        try:
            for coro in asyncio.as_completed(tasks):
                if d := await coro:
                    self.desc_cache[fp] = d
                    return d
        finally:
            [t.cancel() for t in tasks if not t.done()]
        return None
    async def get_descriptors(self, fps):
        await asyncio.gather(*[self.get_descriptor(fp) for fp in fps if fp not in self.desc_cache], return_exceptions=True)
        return {fp: self.desc_cache.get(fp) for fp in fps}
    async def update(self, limit=50, force=False):
        print(f'\n=== Update directory (proxy={self.proxy[0]}:{self.proxy[1]}) ===')
        if not force and self.guards and self.middles and self.exits:
            print(f'  Guard:{len(self.guards)} Middle:{len(self.middles)} Exit:{len(self.exits)}')
            return True
        async def fetch_nodes(typ, url):
            try:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                    async with session.get(url, proxy=f'socks5://{self.proxy[0]}:{self.proxy[1]}', timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        return typ, (await resp.json()).get('relays', [])
            except Exception as e: print(f'  [{typ}] {e}'); return typ, []
        urls = [('G', f'{ONIONOO}?type=relay&running=true&flag=Guard&flag=Stable&limit={limit}'),
                ('M', f'{ONIONOO}?type=relay&running=true&flag=Stable&flag=Fast&limit={limit*2}'),
                ('E', f'{ONIONOO}?type=relay&running=true&flag=Exit&limit={limit}')]
        results, used, nodes = await asyncio.gather(*[fetch_nodes(t, u) for t, u in urls]), set(), {'G': [], 'M': [], 'E': []}
        for typ, relays in results:
            for r in relays:
                flags = r.get('flags', [])
                if typ == 'M' and ('Guard' in flags or 'Exit' in flags): continue
                if typ == 'E' and 'BadExit' in flags: continue
                if (m := re.match(r'^(\d+\.\d+\.\d+\.\d+):(\d+)$', r.get('or_addresses', [''])[0])) and (fp := r.get('fingerprint')) not in used:
                    nodes[typ].append(Node(r.get('nickname'), m[1], int(m[2]), fp, bytes.fromhex(fp), flags))
                    used.add(fp)
        self.guards, self.middles, self.exits = nodes['G'], nodes['M'], nodes['E']
        print(f'  Guard:{len(self.guards)} Middle:{len(self.middles)} Exit:{len(self.exits)}')
        if self.guards and self.exits: self._save_cache()
        return bool(self.guards and self.exits)
    def select_path(self, hops):
        random.shuffle(self.guards); random.shuffle(self.middles); random.shuffle(self.exits)
        if hops == 1: return [self.exits[0]] if self.exits else None
        path, used = [], set()
        for pool in [self.guards] + [self.middles] * (hops - 2) + [self.exits]:
            for n in pool:
                if n.fp not in used: path.append(n); used.add(n.fp); break
        return path if len(path) == hops else None
    async def prepare(self, path):
        descs = await self.get_descriptors([n.fp for n in path if not n.ntor])
        for n in path:
            if not n.ntor:
                if not (d := descs.get(n.fp)) or 'ntor' not in d: raise Exception(f"No ntor key: {n.name}")
                n.ntor, n.ed25519 = d['ntor'], d.get('ed25519')
        return path
# ==================== Connection Helpers ====================
async def connect(proxy, node, timeout=30, fallback_direct=False):
    import socks
    loop = asyncio.get_event_loop()
    def sync_connect():
        tcp = socks.socksocket()
        tcp.set_proxy(socks.SOCKS5, proxy[0], proxy[1])
        tcp.settimeout(timeout)
        tcp.connect((node.addr, node.port))
        tcp.setblocking(False)
        return tcp
    try:
        raw_sock = await asyncio.wait_for(loop.run_in_executor(None, sync_connect), timeout=timeout)
    except Exception as e:
        if not fallback_direct:
            raise Exception(f'SOCKS connect failed for {node.addr}:{node.port}: {e}')
        # 显式测试模式才允许直连 Tor relay；默认不静默绕过 SOCKS。
        import socket
        def direct_connect():
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(timeout)
            tcp.connect((node.addr, node.port))
            tcp.setblocking(False)
            return tcp
        raw_sock = await asyncio.wait_for(loop.run_in_executor(None, direct_connect), timeout=timeout)
    ctx = ssl.create_default_context(); ctx.check_hostname = ctx.verify_mode = False
    reader, writer = await asyncio.wait_for(asyncio.open_connection(sock=raw_sock, ssl=ctx, server_hostname=node.addr), timeout=15)
    writer.write(b'\x00\x00\x07\x00\x06\x00\x03\x00\x04\x00\x05'); await writer.drain()
    await asyncio.wait_for(reader.read(4096), timeout=10)
    writer.write(cell(0, CMD['NETINFO'], struct.pack('>I', int(time.time())) + b'\x04\x04\x00\x00\x00\x00\x00')); await writer.drain()
    return reader, writer
async def build_circuit(d, path, timeout=60):
    reader, writer = await connect(d.proxy, path[0])
    circ = TorCircuit(reader, writer, 0x80000001)
    hops = len(path)
    build_start = time.time()
    try:
        t = TIMEOUT.timeout(1, 'build')
        await asyncio.wait_for(circ.create(path[0].id, path[0].ntor), timeout=t)
        for i, n in enumerate(path[1:], 2):
            t = TIMEOUT.timeout(i, 'build')
            await asyncio.wait_for(circ.extend(n.id, n.ntor, n.addr, n.port, n.ed25519), timeout=t)
        # 记录成功的电路建立时间
        TIMEOUT.record_build(hops, time.time() - build_start)
    except: circ.close(); raise
    return circ
async def build_circuit_with_retry(d, max_retries=3, timeout=45):
    last_error = None
    for attempt in range(max_retries):
        try:
            path = await d.prepare(d.select_path(3))
            return await asyncio.wait_for(build_circuit(d, path), timeout=timeout), path
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1: print(f'  Retry {attempt + 2}/{max_retries}...')
    raise Exception(f'Failed to build circuit after {max_retries} attempts: {last_error}')
@dataclass
class ClientAuth:
    """HS 客户端授权密钥"""
    onion_addr: str                # .onion 地址 (不含 .onion)
    secret_key: bytes              # X25519 私钥 (32字节)
    name: str = ''                 # 可选名称

    @classmethod
    def from_file(cls, filepath: str) -> 'ClientAuth':
        """从 .auth_private 文件加载"""
        with open(filepath, 'r') as f:
            content = f.read().strip()
        # 格式: <onion-addr>:descriptor:x25519:<base32-key>
        parts = content.split(':')
        if len(parts) != 4 or parts[1] != 'descriptor' or parts[2] != 'x25519':
            raise ValueError(f'Invalid auth file format: {filepath}')
        return cls(parts[0].replace('.onion', ''), b32d(parts[3]), filepath.split('/')[-1].replace('.auth_private', ''))

    @classmethod
    def from_base32(cls, onion_addr: str, key_b32: str, name: str = '') -> 'ClientAuth':
        """从 base32 密钥创建"""
        return cls(onion_addr.replace('.onion', ''), b32d(key_b32), name)

    def get_public_key(self) -> bytes:
        """获取对应的公钥"""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        return X25519PrivateKey.from_private_bytes(self.secret_key).public_key().public_bytes_raw()

def hs_desc_decrypt_client_layer(ciphertext: bytes, blinded: bytes, subcred: bytes, client_auth: ClientAuth) -> Optional[bytes]:
    """解密 HS 描述符的客户端授权层"""
    if len(ciphertext) < 84: return None  # 最小: ephemeral_key(32) + auth_clients(52+)
    ephemeral_key = ciphertext[:32]

    # 使用客户端私钥和服务端临时公钥进行 X25519 密钥交换
    client_kp = X25519PrivateKey.from_private_bytes(client_auth.secret_key)
    shared_secret = client_kp.exchange(X25519PublicKey.from_public_bytes(ephemeral_key))

    # 派生密钥
    secret_input = shared_secret + subcred + blinded
    keys = shake_256(b'tor-hs-credential-keys' + struct.pack('>Q', len(secret_input)) + secret_input).digest(64)
    client_id, cookie_key = keys[:8], keys[32:48]

    # 查找匹配的 client-id
    pos, num_clients = 32, ciphertext[32] if len(ciphertext) > 32 else 0
    pos += 1
    for _ in range(num_clients):
        if pos + 52 > len(ciphertext): break
        cid, iv, enc_cookie = ciphertext[pos:pos+8], ciphertext[pos+8:pos+24], ciphertext[pos+24:pos+52]
        pos += 52
        if cid == client_id:
            # 解密 cookie
            cookie = Cipher(algorithms.AES(cookie_key), modes.CTR(iv), default_backend()).decryptor().update(enc_cookie)
            # 使用 cookie 解密剩余内容
            enc_data = ciphertext[pos:]
            if len(enc_data) < 48: return None
            salt, encrypted, mac = enc_data[:16], enc_data[16:-32], enc_data[-32:]
            final_keys = shake_256(blinded + cookie + subcred + salt + b'tor-hs-desc-auth-inner-encrypted-data').digest(80)
            if mac == mac_sha3(final_keys[48:], struct.pack('>Q', 16) + salt + encrypted):
                return Cipher(algorithms.AES(final_keys[:32]), modes.CTR(final_keys[32:48]), default_backend()).decryptor().update(encrypted)
    return None

# ==================== PoW (Proof of Work) ====================
class HsPowSolver:
    """HS PoW 求解器 (Equi-X v1)"""
    def __init__(self, seed: bytes, effort: int):
        self.seed = seed
        self.effort = effort
        self.nonce = None
        self.solution = None

    def solve(self, blinded_id: bytes, timeout: float = 30.0) -> Optional[Tuple[bytes, bytes]]:
        """
        求解 PoW 挑战
        返回: (nonce, solution) 或 None
        注意: Equi-X 在纯 Python 中非常慢，建议使用 C 扩展
        """
        import time
        start = time.time()
        challenge = self.seed + blinded_id

        # Equi-X 简化版 (实际需要完整实现)
        # 这里使用 Blake2b 模拟，实际应该是 Equi-X
        for i in range(2**32):
            if time.time() - start > timeout:
                return None
            nonce = struct.pack('<I', i) + os.urandom(12)  # 16字节 nonce
            h = hashlib.blake2b(challenge + nonce + struct.pack('<I', self.effort), digest_size=16).digest()
            # 检查前导零 (根据 effort 调整难度)
            leading_zeros = sum(1 for b in h if b == 0)
            if leading_zeros >= (self.effort // 1000 + 1):
                self.nonce = nonce
                self.solution = h
                return nonce, h
        return None

    def increase_effort(self, factor: float = 1.5):
        """增加努力值"""
        self.effort = int(self.effort * factor)

    def build_extension(self) -> bytes:
        """构建 INTRODUCE1 的 PoW 扩展"""
        if not self.nonce or not self.solution:
            return b''
        # PoW extension format: type(1) + version(1) + nonce(16) + effort(4) + seed(32) + solution(16)
        return bytes([0x01, 0x01]) + self.nonce + struct.pack('<I', self.effort) + self.seed + self.solution

@dataclass
class CachedDescriptor:
    """带时间戳的 HS Descriptor 缓存"""
    desc: dict
    fetched_at: float
    period: int
    valid_until: float = 0.0

    def __post_init__(self):
        # 描述符有效期: 当前 time period 结束 + 60分钟缓冲
        period_end = (self.period + 1) * 1440 * 60 + 720 * 60
        self.valid_until = period_end + 3600  # 额外1小时缓冲

    def is_valid(self) -> bool:
        now = time.time()
        # 有效条件: 未过期且获取时间不超过30分钟
        return now < self.valid_until and (now - self.fetched_at) < 1800

# ==================== HSClient ====================
class HSClient:
    def __init__(self, directory, client_auths: Dict[str, ClientAuth] = None):
        self.d = directory
        self.ipt_experiences: Dict[str, IptExperience] = {}  # IPT标识 -> 经验记录
        self.desc_cache: Dict[str, CachedDescriptor] = {}    # onion_addr -> 缓存描述符
        self.client_auths = client_auths or {}               # onion_addr -> ClientAuth
        self.pow_solvers: Dict[str, HsPowSolver] = {}        # onion_addr -> PoW求解器
        self._load_desc_cache()

    def _load_desc_cache(self):
        """从磁盘加载 HS 描述符缓存"""
        def deserialize_desc(data):
            """将 hex 字符串转回 bytes"""
            result = {'intro_points': [], 'single_onion': data.get('single_onion', False),
                      'pow_params': data.get('pow_params'), 'requires_auth': data.get('requires_auth', False)}
            for ip in data.get('intro_points', []):
                dip = {}
                for k, v in ip.items():
                    dip[k] = bytes.fromhex(v) if isinstance(v, str) and len(v) % 2 == 0 and k in ('link_specifiers', 'ntor_key', 'enc_key', 'auth_key') else v
                result['intro_points'].append(dip)
            if data.get('pow_params') and data['pow_params'].get('seed'):
                result['pow_params'] = dict(data['pow_params'])
                result['pow_params']['seed'] = bytes.fromhex(data['pow_params']['seed'])
            return result
        try:
            with open(HS_DESC_CACHE_PATH) as f: d = json.load(f)
            loaded = 0
            for onion_key, cache_data in d.items():
                desc = deserialize_desc(cache_data['desc'])
                cached = CachedDescriptor(desc, cache_data['fetched_at'], cache_data['period'])
                if cached.is_valid(): self.desc_cache[onion_key] = cached; loaded += 1
            loaded and print(f'  Loaded {loaded} cached HS descriptors')
        except Exception: pass

    def _save_desc_cache(self):
        """保存 HS 描述符缓存到磁盘"""
        def serialize_desc(desc):
            """将描述符中的 bytes 转为 hex 字符串"""
            result = {'intro_points': [], 'single_onion': desc.get('single_onion', False),
                      'pow_params': desc.get('pow_params'), 'requires_auth': desc.get('requires_auth', False)}
            for ip in desc.get('intro_points', []):
                sip = {}
                for k, v in ip.items():
                    sip[k] = v.hex() if isinstance(v, bytes) else v
                result['intro_points'].append(sip)
            if desc.get('pow_params') and desc['pow_params'].get('seed'):
                result['pow_params'] = dict(desc['pow_params'])
                result['pow_params']['seed'] = desc['pow_params']['seed'].hex()
            return result
        try:
            data = {k: {'desc': serialize_desc(v.desc), 'fetched_at': v.fetched_at, 'period': v.period} for k, v in self.desc_cache.items() if v.is_valid()}
            tmp = HS_DESC_CACHE_PATH + '.tmp'
            with open(tmp, 'w') as f: json.dump(data, f)
            os.replace(tmp, HS_DESC_CACHE_PATH)
        except Exception: pass

    def add_client_auth(self, auth: ClientAuth):
        """添加客户端授权密钥"""
        self.client_auths[auth.onion_addr] = auth

    def load_auth_dir(self, dir_path: str):
        """从目录加载所有 .auth_private 文件"""
        import glob
        for f in glob.glob(f'{dir_path}/*.auth_private'):
            try:
                auth = ClientAuth.from_file(f)
                self.client_auths[auth.onion_addr] = auth
                print(f'  Loaded auth for {auth.onion_addr[:16]}...onion')
            except Exception as e:
                print(f'  Failed to load {f}: {e}')

    def _init_pow(self, onion_key: str, pow_params: dict):
        """初始化 PoW 求解器"""
        if pow_params and onion_key not in self.pow_solvers:
            self.pow_solvers[onion_key] = HsPowSolver(pow_params['seed'], pow_params['suggested_effort'])
            print(f'  PoW initialized (effort={pow_params["suggested_effort"]})')

    def _ipt_id(self, intro) -> str:
        """生成 intro point 的唯一标识"""
        if enc_key := intro.get('enc_key'): return enc_key.hex()
        if auth_key := intro.get('auth_key'): return auth_key.hex()
        if specs := intro.get('link_specifiers'):
            addr, port, nid = self._parse_link_specs(specs)
            if nid: return nid.hex()
        return str(hash(str(intro)))

    def _get_experience(self, intro) -> IptExperience:
        """获取或创建 IPT 经验记录"""
        ipt_id = self._ipt_id(intro)
        if ipt_id not in self.ipt_experiences:
            self.ipt_experiences[ipt_id] = IptExperience()
        return self.ipt_experiences[ipt_id]

    def _sort_intro_points(self, intro_points: list) -> list:
        """按经验排序 intro points: 成功 > 未试 > 失败"""
        now = time.time()
        def sort_key(ip):
            exp = self._get_experience(ip)
            # 如果在退避期内，降低优先级
            if exp.outcome == IptOutcome.FAILED and now < exp.retry_after:
                return (3, exp.retry_after, 0)  # 退避中的放最后
            return exp.sort_key()
        return sorted(intro_points, key=sort_key)
    async def connect(self, onion_addr, port=80):
        print(f'\n=== Connect to Hidden Service ===\n  Address: {onion_addr}')
        pubkey, ver = parse_onion_v3(onion_addr)
        onion_key = pubkey.hex()
        print(f'  Version: v{ver}')

        # 检查描述符缓存
        if onion_key in self.desc_cache and self.desc_cache[onion_key].is_valid():
            desc = self.desc_cache[onion_key].desc
            age = time.time() - self.desc_cache[onion_key].fetched_at
            print(f'\n[1/6] Using cached descriptor ({age:.0f}s old, {len(desc["intro_points"])} intro points)')
        else:
            print('\n[1/6] Fetching HS descriptor...')
            if not (desc := await self._fetch_descriptor(pubkey)):
                raise Exception('Cannot fetch HS descriptor')
            # 缓存描述符
            self.desc_cache[onion_key] = CachedDescriptor(desc, time.time(), get_time_period())
            self._save_desc_cache()
            print(f'  Found {len(desc["intro_points"])} intro points (cached)')

        # 显示服务属性
        flags = []
        if desc.get('single_onion'): flags.append('Single-Onion')
        if desc.get('pow_params'): flags.append(f'PoW(effort={desc["pow_params"]["suggested_effort"]})')
        if desc.get('requires_auth'): flags.append('Requires-Auth')
        if flags: print(f'  Service flags: {", ".join(flags)}')

        # 检查是否需要认证但没有密钥
        if desc.get('requires_auth') and not desc.get('intro_points'):
            raise Exception('Service requires client authorization. Use add_client_auth() or load_auth_dir()')

        # 初始化 PoW (如果需要)
        if desc.get('pow_params'):
            self._init_pow(onion_key, desc['pow_params'])

        # 按经验排序 intro points
        sorted_ipts = self._sort_intro_points(desc['intro_points'])
        for i, ip in enumerate(sorted_ipts[:3]):
            exp = self._get_experience(ip)
            status = {IptOutcome.SUCCESS: '✓', IptOutcome.UNTRIED: '?', IptOutcome.FAILED: '✗'}[exp.outcome]
            print(f'    IPT#{i+1} [{status}] {exp.outcome.name} (dur={exp.duration:.2f}s, fails={exp.fail_count})')

        print('\n[2/6] Selecting intro point (by experience)...')
        rend_circ, rend_path, rend_cookie = None, None, None
        intro_base_path, last_error = None, None  # 复用 Guard+Middle 路径

        # 尝试多个 intro points
        for ipt_attempt, intro in enumerate(sorted_ipts[:5]):
            exp = self._get_experience(intro)
            if exp.outcome == IptOutcome.FAILED and time.time() < exp.retry_after:
                print(f'    IPT#{ipt_attempt+1}: Skipping (retry after {int(exp.retry_after - time.time())}s)')
                continue

            print(f'    IPT#{ipt_attempt+1}: Trying ({exp.outcome.name})...')
            ipt_start = time.time()

            try:
                # [3/6] 建立 rendezvous 电路 (如果还没有)
                if not rend_circ:
                    print('\n[3/6] Building rendezvous circuit...')
                    rend_circ, rend_path = await build_circuit_with_retry(self.d)
                    print(f'  Rendezvous: {rend_path[-1].name}')
                    print('\n[4/6] Establishing rendezvous...')
                    rend_cookie = os.urandom(20)
                    await rend_circ.send(RELAY['ESTABLISH_RENDEZVOUS'], 0, rend_cookie)
                    if not (r := await rend_circ.recv(TIMEOUT.timeout(3, 'rtt', 2.0))) or r['cmd'] != RELAY['RENDEZVOUS_ESTABLISHED']:
                        rend_circ.close(); rend_circ = None
                        raise Exception(f'ESTABLISH_RENDEZVOUS failed: {r}')
                    print('  Rendezvous established')

                print('\n[5/6] Connecting to intro point...')
                intro_addr, intro_port, intro_id = self._parse_link_specs(intro.get('link_specifiers', b''))
                intro_ntor = intro.get('ntor_key') or (d.get('ntor') if intro_id and (d := await self.d.get_descriptor(intro_id.hex().upper())) else None)
                if not intro_ntor: raise Exception('Cannot get intro ntor key')
                intro_node = Node('Intro', intro_addr, intro_port, intro_id.hex().upper() if intro_id else '', intro_id, ntor=intro_ntor)

                intro_circ = None
                # 复用 Guard+Middle 路径 (如果有)
                if not intro_base_path:
                    intro_base_path = await self.d.prepare([random.choice(self.d.guards), random.choice(self.d.middles or self.d.guards)])
                    print(f'    Base path: {intro_base_path[0].name} -> {intro_base_path[1].name}')

                for attempt in range(2):  # 减少重试次数，因为已经有 IPT 级别的重试
                    try:
                        intro_reader, intro_writer = await asyncio.wait_for(connect(self.d.proxy, intro_base_path[0]), timeout=TIMEOUT.timeout(1, 'build'))
                        intro_circ = TorCircuit(intro_reader, intro_writer, 0x80000003 + ipt_attempt * 10 + attempt)
                        await asyncio.wait_for(intro_circ.create(intro_base_path[0].id, intro_base_path[0].ntor), timeout=TIMEOUT.timeout(1, 'build'))
                        await asyncio.wait_for(intro_circ.extend(intro_base_path[1].id, intro_base_path[1].ntor, intro_base_path[1].addr, intro_base_path[1].port), timeout=TIMEOUT.timeout(2, 'build'))
                        await asyncio.wait_for(intro_circ.extend(intro_node.id, intro_node.ntor, intro_node.addr, intro_node.port), timeout=TIMEOUT.timeout(3, 'build'))
                        break
                    except Exception as e:
                        if intro_circ: intro_circ.close()
                        if attempt >= 1:
                            # 基础路径可能有问题，重新选择
                            intro_base_path = None
                            raise Exception(f'Failed to connect to intro point: {e}')
                        print(f'  Intro retry {attempt + 2}/2...')

                print('\n[6/6] Sending INTRODUCE1...')
                # 检查是否需要 PoW
                pow_ext = b''
                if onion_key in self.pow_solvers:
                    solver = self.pow_solvers[onion_key]
                    blinded = blind_pubkey(pubkey, get_time_period())
                    print(f'    Solving PoW (effort={solver.effort})...')
                    if solver.solve(blinded, timeout=60):
                        pow_ext = solver.build_extension()
                        print(f'    PoW solved!')
                    else:
                        print(f'    PoW timeout, trying without...')

                await intro_circ.send(RELAY['INTRODUCE1'], 0, self._build_intro1(intro, rend_cookie, rend_path[-1], pubkey, pow_ext))
                r = await intro_circ.recv(TIMEOUT.timeout(3, 'rtt', 2.0))
                if not r or r['cmd'] != RELAY['INTRODUCE_ACK']:
                    intro_circ.close()
                    raise Exception(f'INTRODUCE1 failed: {r}')
                # 检查 INTRODUCE_ACK 状态
                ack_status = r['data'][0] if r['data'] else 0
                if ack_status != 0:
                    intro_circ.close()
                    # 状态 1 = 需要更多 PoW 努力
                    if ack_status == 1 and onion_key in self.pow_solvers:
                        self.pow_solvers[onion_key].increase_effort()
                        print(f'    Service requested more PoW effort (new={self.pow_solvers[onion_key].effort})')
                    raise Exception(f'INTRODUCE_ACK status: {ack_status}')
                intro_circ.close()

                print('\nWaiting for RENDEZVOUS2...')
                if not (r := await rend_circ.recv(TIMEOUT.timeout(4, 'rtt', 3.0))) or r['cmd'] != RELAY['RENDEZVOUS2']:
                    raise Exception(f'RENDEZVOUS2 failed: {r}')

                # 记录成功
                duration = time.time() - ipt_start
                exp.record_success(duration)
                print(f'  Hidden Service connected! (IPT took {duration:.2f}s)')
                self._process_rend2(rend_circ, r['data'], intro)
                return rend_circ

            except Exception as e:
                # 记录失败
                duration = time.time() - ipt_start
                exp.record_failure(duration)
                print(f'    IPT#{ipt_attempt+1} failed ({duration:.2f}s): {e}')
                last_error = e
                # rend_circ 可能需要重建
                if rend_circ and 'RENDEZVOUS' in str(e):
                    rend_circ.close(); rend_circ = None

        if rend_circ: rend_circ.close()
        raise Exception(f'All intro points failed. Last error: {last_error}')
    async def _fetch_descriptor(self, pubkey):
        if not self.d.consensus: await self.d.fetch_consensus()
        self.d.parse_srv()
        tp_cur, tp_prev = get_time_period(), get_time_period() - 1
        combos = [(n, s, p) for n, s, p in [('PREV_SRV+CUR_PERIOD', self.d.srv_prev, tp_cur), ('CUR_SRV+CUR_PERIOD', self.d.srv, tp_cur),
                                             ('PREV_SRV+PREV_PERIOD', self.d.srv_prev, tp_prev), ('CUR_SRV+PREV_PERIOD', self.d.srv, tp_prev)] if s]
        async def try_combo(name, srv, period):
            print(f'\n  === Trying {name} (period={period}) ===')
            blinded = blind_pubkey(pubkey, period)
            print(f'  Blinded key: {blinded.hex()}')
            if not (hsdirs := await self.d.get_responsible_hsdirs(blinded, period, srv)): return None
            blinded_b64 = base64.b64encode(blinded).decode().rstrip('=')
            async def try_hsdir(hsdir, idx):
                circ = None
                try:
                    print(f'    Trying HSDir #{idx+1}: {hsdir.name}...')
                    d = await self.d.get_descriptor(hsdir.fp)
                    if not d or 'ntor' not in d: return None
                    hsdir.ntor = d['ntor']
                    guard, mid = random.choice(self.d.guards), random.choice(self.d.middles or self.d.guards)
                    path = await self.d.prepare([guard, mid])
                    print(f'    Try #{idx+1}: {guard.name} -> {mid.name} -> {hsdir.name}')
                    reader, writer = await connect(self.d.proxy, path[0])
                    circ = TorCircuit(reader, writer, 0x80000002 + idx)
                    await circ.create(path[0].id, path[0].ntor)
                    await circ.extend(path[1].id, path[1].ntor, path[1].addr, path[1].port)
                    await circ.extend(hsdir.id, hsdir.ntor, hsdir.addr, hsdir.port)
                    await circ.send(RELAY['BEGIN_DIR'], 1)
                    if not (r := await circ.recv()) or r['cmd'] != RELAY['CONNECTED']: return None
                    await circ.send(RELAY['DATA'], 1, f'GET /tor/hs/3/{blinded_b64} HTTP/1.0\r\nHost: {hsdir.addr}\r\n\r\n'.encode())
                    resp_parts = []
                    for _ in range(100):
                        if not (r := await circ.recv()): break
                        if r['cmd'] == RELAY['DATA']: resp_parts.append(r['data'])
                        elif r['cmd'] == RELAY['END']: break
                    resp = b''.join(resp_parts)
                    if b'\r\n\r\n' in resp:
                        hdr, body = resp.split(b'\r\n\r\n', 1)
                        resp = decode_chunked(body) if b'transfer-encoding: chunked' in hdr.lower() else body
                    if b'-----BEGIN MESSAGE-----' not in resp: return None
                    is_valid, err = verify_hs_descriptor(resp, blinded)
                    if not is_valid:
                        print(f'    HSDir #{idx+1}: Signature verification failed: {err}')
                        return None
                    return self._parse_descriptor(resp, pubkey, blinded, period)
                except Exception as e:
                    print(f'    HSDir #{idx+1} error: {e}')
                    return None
                finally:
                    if circ: circ.close()
            async def race_hsdirs(batch, offset=0):
                tasks = [asyncio.create_task(try_hsdir(h, i)) for i, h in enumerate(batch, offset)]
                try:
                    for coro in asyncio.as_completed(tasks):
                        if result := await coro: return result
                finally:
                    for t in tasks:
                        if not t.done(): t.cancel()
                return None
            if result := await race_hsdirs(hsdirs[:3]): return result
            for start in range(3, len(hsdirs), 3):
                if result := await race_hsdirs(hsdirs[start:start+3], start): return result
            return None
        for period_combos in ([c for c in combos if c[2] == tp_cur], [c for c in combos if c[2] == tp_prev]):
            if not period_combos: continue
            tasks = [asyncio.create_task(try_combo(*c)) for c in period_combos]
            try:
                for coro in asyncio.as_completed(tasks):
                    if result := await coro: return result
            finally:
                for t in tasks:
                    if not t.done(): t.cancel()
        return None
    def _parse_descriptor(self, raw, pubkey, blinded, period):
        desc, txt = {'intro_points': [], 'single_onion': False, 'pow_params': None, 'requires_auth': False}, raw.decode('latin1', errors='replace')
        rev, subcred = int(m[1]) if (m := re.search(r'revision-counter (\d+)', txt)) else 0, hs_subcredential(pubkey, blinded)
        onion_addr = base64.b32encode(pubkey + sha3_256(b'.onion checksum' + pubkey + b'\x03').digest()[:2] + b'\x03').decode().lower()

        # 检测 Single Onion Service (第一层解密前)
        if 'single-onion-service' in txt:
            desc['single_onion'] = True

        # 获取该服务的客户端授权密钥 (如果有)
        client_auth = self.client_auths.get(onion_addr.replace('.onion', ''))

        for layer in range(2):
            if '-----BEGIN MESSAGE-----' in txt and '-----END MESSAGE-----' in txt:
                b64 = txt[txt.find('-----BEGIN MESSAGE-----')+23:txt.find('-----END MESSAGE-----')].replace('\n', '')
                ciphertext = base64.b64decode(b64)

                # 尝试解密
                dec = None
                if layer == 0:
                    # 第一层: superencrypted-data, 可能需要 client auth
                    if client_auth:
                        dec = hs_desc_decrypt_client_layer(ciphertext, blinded, subcred, client_auth)
                        if dec: print(f'    [Client Auth] Decrypted with auth key')
                    if not dec:
                        dec = hs_desc_decrypt(ciphertext, blinded, subcred, rev, b'hsdir-superencrypted-data')
                    if not dec and not client_auth:
                        # 可能需要认证但没有密钥
                        desc['requires_auth'] = True
                else:
                    # 第二层: encrypted-data
                    dec = hs_desc_decrypt(ciphertext, blinded, subcred, rev, b'hsdir-encrypted-data')

                if dec:
                    txt = dec.decode('latin1', errors='replace')
                    if 'single-onion-service' in txt:
                        desc['single_onion'] = True

        # 解析 PoW 参数 (为后续实现准备)
        if m := re.search(r'pow-params v1 ([A-Za-z0-9+/=]+) (\d+)', txt):
            desc['pow_params'] = {'version': 1, 'seed': b64d(m[1]), 'suggested_effort': int(m[2])}
        for block in txt.split('introduction-point ')[1:]:
            lines, ip = block.split('\n'), {}
            try: ip['link_specifiers'] = b64d(lines[0].strip())
            except: pass
            for i, ln in enumerate(lines[1:]):
                if ln.startswith('onion-key ntor '): ip['ntor_key'] = b64d(ln.split()[2])
                elif ln.startswith('enc-key ntor '): ip['enc_key'] = b64d(ln.split()[2])
                elif ln.startswith('auth-key'):
                    cert_lines, in_cert = [], False
                    for j in range(i+2, min(i+15, len(lines))):
                        if '-----BEGIN ED25519 CERT-----' in lines[j]: in_cert = True
                        elif '-----END ED25519 CERT-----' in lines[j]: break
                        elif in_cert: cert_lines.append(lines[j].strip())
                    if cert_lines and len(cert := b64d(''.join(cert_lines))) >= 39: ip['auth_key'] = cert[7:39]
            if ip.get('enc_key') or ip.get('ntor_key'): desc['intro_points'].append(ip)
        return desc
    def _parse_link_specs(self, data):
        if len(data) < 2: return None, None, None
        addr, port, nid, i, n = None, None, None, 1, data[0]
        for _ in range(n):
            if i + 2 > len(data): break
            typ, sz, d = data[i], data[i+1], data[i+2:i+2+data[i+1]]; i += 2 + sz
            if typ == 0 and sz == 6: addr, port = '.'.join(str(b) for b in d[:4]), (d[4] << 8) | d[5]
            elif typ == 2 and sz == 20: nid = d
        return addr, port, nid
    def _build_intro1(self, intro, rend_cookie, rend_node, hs_pub, pow_ext: bytes = b''):
        enc_key, auth_key = intro.get('enc_key'), (intro.get('auth_key', b'\x00' * 32)[:32]).ljust(32, b'\x00')
        if not enc_key or len(enc_key) != 32: raise Exception('Missing enc_key')
        client_kp, client_pub = X25519PrivateKey.generate(), None
        client_pub = client_kp.public_key().public_bytes_raw()
        # 计算扩展数量
        n_extensions = 1 if pow_ext else 0
        payload = bytearray(b'\x00' * 20 + b'\x02' + struct.pack('>H', 32) + auth_key + bytes([n_extensions]))
        if pow_ext: payload.extend(pow_ext)  # 添加 PoW 扩展
        plaintext = bytearray(rend_cookie + b'\x00\x01' + struct.pack('>H', 32) + rend_node.ntor)
        rend_ip = bytes(int(x) for x in rend_node.addr.split('.'))
        plaintext.extend(bytes([2, 0, 6]) + rend_ip + struct.pack('>H', rend_node.port) + bytes([2, 20]) + rend_node.id)
        shared = client_kp.exchange(X25519PublicKey.from_public_bytes(enc_key))
        blinded = blind_pubkey(hs_pub, get_time_period())
        subcred = hs_subcredential(hs_pub, blinded)
        keys = shake_256(shared + auth_key + client_pub + enc_key + PROTOID + PROTOID + b':hs_key_extract' + PROTOID + b':hs_key_expand' + subcred).digest(64)
        encrypted = Cipher(algorithms.AES(keys[:32]), modes.CTR(b'\x00' * 16), default_backend()).encryptor().update(bytes(plaintext))
        payload.extend(client_pub + encrypted + mac_sha3(keys[32:], bytes(payload) + client_pub + encrypted))
        self._client_kp, self._enc_key, self._auth_key = client_kp, enc_key, auth_key
        return bytes(payload)
    def _process_rend2(self, circ, data, intro):
        if len(data) < 64: raise Exception(f'RENDEZVOUS2 too short: {len(data)}')
        server_pub, server_auth, client_pub = data[:32], data[32:64], self._client_kp.public_key().public_bytes_raw()
        dh1, dh2 = self._client_kp.exchange(X25519PublicKey.from_public_bytes(server_pub)), self._client_kp.exchange(X25519PublicKey.from_public_bytes(self._enc_key))
        rend_input = dh1 + dh2 + self._auth_key + self._enc_key + client_pub + server_pub + PROTOID
        ntor_seed, ntor_verify = mac_sha3(rend_input, PROTOID + b':hs_key_extract'), mac_sha3(rend_input, PROTOID + b':hs_verify')
        if mac_sha3(ntor_verify + self._auth_key + self._enc_key + server_pub + client_pub + PROTOID + b'Server', PROTOID + b':hs_mac') != server_auth:
            raise Exception('RENDEZVOUS2 auth failed')
        keys = shake_256(ntor_seed + PROTOID + b':hs_key_expand').digest(128)
        circ._add_hop(keys[:32], keys[32:64], keys[64:96], keys[96:128], is_hs=True)
# ==================== TLS Stream ====================
class TLSStream:
    def __init__(self, circ, sid):
        self.circ, self.sid, self.incoming, self.outgoing = circ, sid, ssl.MemoryBIO(), ssl.MemoryBIO()
    async def flush(self):
        if data := self.outgoing.read():
            for i in range(0, len(data), 498): await self.circ.send(RELAY['DATA'], self.sid, data[i:i+498])
    async def recv(self):
        if (r := await self.circ.recv(30)) and r['cmd'] == RELAY['DATA']: self.incoming.write(r['data']); return True
        return False
# ==================== Main ====================
def parse_url(url):
    from urllib.parse import urlparse
    p = urlparse(url if '://' in url else 'http://' + url)
    use_tls = p.scheme == 'https'
    return p.hostname or '', p.port or (443 if use_tls else 80), (p.path or '/') + ('?' + p.query if p.query else ''), use_tls
async def async_main():
    if len(sys.argv) < 2:
        print('Usage: python3 torhs-circuit.py <onion_url>\nExamples:\n  python3 torhs-circuit.py duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion\n  python3 torhs-circuit.py http://xxx.onion/wiki/index.php\n  python3 torhs-circuit.py https://xxx.onion/path?query=1')
        return
    host, port, path, use_tls = parse_url(sys.argv[1])
    onion_addr = host.lower().replace('.onion', '').strip()
    if len(onion_addr) != 56: print(f'Error: Invalid onion v3 address (need 56 chars, got {len(onion_addr)})'); return
    onion_host = onion_addr + '.onion'
    print(f'\n=== Tor Hidden Service Client (Async) ===\n  Host: {onion_host}\n  Port: {port} ({"HTTPS" if use_tls else "HTTP"})\n  Path: {path}')
    d = TorDirectory()
    if not await d.update(50): print('Failed to get nodes'); return
    try:
        circ = await HSClient(d).connect(onion_host)
        print(f'\nSending {"HTTPS" if use_tls else "HTTP"} request...')
        await circ.send(RELAY['BEGIN'], 1, f'{onion_host}:{port}\x00'.encode())
        if not (r := await circ.recv()) or r['cmd'] != RELAY['CONNECTED']:
            if r and r['cmd'] == RELAY['END']:
                reasons = {1:'MISC', 2:'RESOLVEFAILED', 3:'CONNECTREFUSED', 4:'EXITPOLICY', 5:'DESTROY', 6:'DONE/REFUSED', 7:'TIMEOUT', 8:'NOROUTE', 9:'HIBERNATING'}
                raise Exception(f'Connection to port {port} refused: {reasons.get(r["data"][0], r["data"][0]) if r["data"] else "UNKNOWN"}' + (f'\n  Hint: Try HTTP instead' if use_tls else ''))
            raise Exception(f'BEGIN failed: {r}')
        req = f'GET {path} HTTP/1.1\r\nHost: {onion_host}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n'.encode()
        if use_tls:
            tls = TLSStream(circ, 1)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = ctx.verify_mode = False
            tls_sock = ctx.wrap_bio(tls.incoming, tls.outgoing, server_hostname=onion_host)
            while True:
                try: tls_sock.do_handshake(); break
                except ssl.SSLWantReadError: await tls.flush(); await tls.recv()
                except ssl.SSLWantWriteError: await tls.flush()
            tls_sock.write(req); await tls.flush()
            resp = b''
            while len(resp) < 100000:
                await tls.recv()
                try:
                    if not (data := tls_sock.read(4096)): break
                    resp += data
                except ssl.SSLWantReadError: continue
                except ssl.SSLZeroReturnError: break
        else:
            await circ.send(RELAY['DATA'], 1, req)
            resp = b''
            for _ in range(200):
                if not (r := await circ.recv()): break
                if r['cmd'] == RELAY['DATA']: resp += r['data']
                elif r['cmd'] == RELAY['END']: break
        print(f'\n=== Response ({len(resp := parse_http(resp))} bytes) ===\n{resp.decode(errors="replace")[:3000]}')
        circ.close()
        print('\n*** Connection successful! ***')
    except Exception as e:
        import traceback; print(f'\nError: {e}'); traceback.print_exc()
if __name__ == '__main__':
    asyncio.run(async_main())