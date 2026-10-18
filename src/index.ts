import { createHash, createHmac, createPrivateKey, createPublicKey, randomBytes, sign, verify, type KeyObject } from 'node:crypto';
import { mkdirSync, readFileSync, openSync, closeSync, writeFileSync, chmodSync, renameSync, unlinkSync, existsSync } from 'node:fs';
import { homedir, platform, arch } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { request as httpsRequest } from 'node:https';
import { setTimeout as delay } from 'node:timers/promises';

type Json = Record<string, any>;
export interface Lease {
  v: number; kid: string; product: string; user: string; email: string; machine: string; binding: string;
  modules: string[]; issued: string; expires: string; terms: number;
  heartbeat?: {interval_seconds: number; grace_seconds: number} | null;
}
export interface Module { name: string; description?: string; free: boolean; have: boolean; requested?: boolean }
export interface AccessRequest { id: string; modules: string[]; note?: string; status: string; granted?: string[]; until?: string; answer?: string }
export interface Config {
  product: string; keys: Record<string, string>; version?: string; server?: string; directory?: string;
  onSignIn?: (url: string, code: string) => void | Promise<void>;
  /** Platform integration/testing seam. Never take this value from an end user. */
  machineBinding?: () => string;
  /** Seconds since the Unix epoch. */
  clock?: () => number;
  signal?: AbortSignal;
  /** Optional trusted TLS root bundle; hostname verification stays enabled. */
  caBundle?: string;
}

export class LicenseboxError extends Error {
  constructor(public readonly code: string, detail = code.replaceAll('_', ' '), public readonly status = 0) {
    super(`licensebox: ${detail}`); this.name = 'LicenseboxError';
  }
}
export class PolicyError extends LicenseboxError { override name = 'PolicyError'; }
export class ModuleError extends LicenseboxError {
  constructor(public readonly product: string, public readonly module: string, public readonly email: string) {
    super('module_denied', `${product}: ${module} is not licensed to ${email}`); this.name = 'ModuleError';
  }
}

const sources = new Set(['linux-dmi', 'linux-device-tree', 'linux-machine-id', 'windows-smbios', 'macos-platform']);
const policies = new Set(['seat_transferred', 'location_denied', 'location_unknown', 'machine_changed']);
const calls = new Set(['renew', 'modules', 'request', 'requests', 'access-link']);
const limit = 1 << 20;
const privatePrefix = Buffer.from('302e020100300506032b657004220420', 'hex');
const publicPrefix = Buffer.from('302a300506032b6570032100', 'hex');
const encode = (value: Uint8Array): string => Buffer.from(value).toString('base64url');
function decode(value: string, size?: number): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new LicenseboxError('malformed', 'invalid base64url value');
  const bytes = Buffer.from(value, 'base64url');
  if (encode(bytes) !== value || size !== undefined && bytes.length !== size) throw new LicenseboxError('malformed', 'invalid base64url value');
  return bytes;
}
function validBinding(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parts = value.split(':');
  return parts.length === 3 && parts[0] === 'm1' && sources.has(parts[1]) && /^[0-9a-f]{64}$/.test(parts[2]);
}
export function deriveBinding(product: string, source: string, rawId: string): string {
  if (!product || /[\r\n]/.test(product) || !sources.has(source)) throw new LicenseboxError('identity_unavailable');
  const id = rawId.replace(/^\0+|\0+$/g, '').trim().toLowerCase().replaceAll('-', '');
  if (!/^[0-9a-f]+$/.test(id) || id.length % 2) throw new LicenseboxError('identity_unavailable');
  const bytes = Buffer.from(id, 'hex');
  if (bytes.length < 8 || bytes.length > 32 || source !== 'linux-device-tree' && bytes.length !== 16 || bytes.every(x => x === 0) || bytes.every(x => x === 255)) throw new LicenseboxError('identity_unavailable');
  const key = createHash('sha256').update(`licensebox machine binding v1\n${product}`).digest();
  return `m1:${source}:${createHmac('sha256', key).update(`${source}\n${id}`).digest('hex')}`;
}
export function nativeBinding(product: string): string {
  if (platform() === 'linux') {
    for (const [path, source] of [['/sys/class/dmi/id/product_uuid', 'linux-dmi'], ['/sys/firmware/devicetree/base/serial-number', 'linux-device-tree'], ['/etc/machine-id', 'linux-machine-id'], ['/var/lib/dbus/machine-id', 'linux-machine-id']]) {
      try { return deriveBinding(product, source, readFileSync(path, 'utf8')); } catch { /* try next native source */ }
    }
  } else if (platform() === 'darwin') {
    try {
      const output = execFileSync('/usr/sbin/ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], {timeout: 3000, maxBuffer: limit, encoding: 'utf8'});
      const id = /"IOPlatformUUID"\s*=\s*"([0-9a-fA-F-]{36})"/.exec(output)?.[1];
      if (id) return deriveBinding(product, 'macos-platform', id);
    } catch { /* fail closed */ }
  }
  // Windows requires a native SMBIOS host adapter; browser/WASM identity is not available.
  throw new LicenseboxError('identity_unavailable', 'a stable native machine identity is unavailable on this runtime');
}
const stamp = (value: number): string => new Date(Math.floor(value) * 1000).toISOString().replace('.000Z', 'Z');
function epoch(value: unknown): number {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(value)) throw new LicenseboxError('malformed', 'invalid timestamp');
  const result = Date.parse(value) / 1000;
  if (!Number.isFinite(result)) throw new LicenseboxError('malformed', 'invalid timestamp');
  return result;
}
function parse(token: string): { value: Lease; payload: Buffer; signature: Buffer } {
  const parts = token.trim().split('.');
  if (parts.length !== 2) throw new LicenseboxError('malformed', 'invalid lease token');
  const payload = decode(parts[0]), signature = decode(parts[1], 64);
  let value: unknown;
  try { value = JSON.parse(payload.toString('utf8')); } catch { throw new LicenseboxError('malformed', 'invalid lease JSON'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new LicenseboxError('malformed');
  return {value: value as Lease, payload, signature};
}
export function verifyLease(token: string, product: string, keys: Record<string, string>, now: number, allowExpired = false): Lease {
  const {value, payload, signature} = parse(token);
  if (value.v !== 2) throw new LicenseboxError('version', 'unsupported lease version; update the application');
  if (!Object.hasOwn(keys, value.kid)) throw new LicenseboxError('unknown_key');
  const key = createPublicKey({key: Buffer.concat([publicPrefix, decode(keys[value.kid], 32)]), format: 'der', type: 'spki'});
  if (!verify(null, Buffer.concat([Buffer.from('licensebox lease v2\n'), payload]), key, signature)) throw new LicenseboxError('bad_signature');
  if (value.product !== product || !validBinding(value.binding)) throw new LicenseboxError('malformed', 'lease product or native binding does not match');
  decode(value.machine, 32);
  if (!Array.isArray(value.modules) || value.modules.some(x => typeof x !== 'string')) throw new LicenseboxError('malformed', 'invalid module list');
  const heartbeat = value.heartbeat;
  if (heartbeat != null) {
    if (typeof heartbeat !== 'object' || Array.isArray(heartbeat)) throw new LicenseboxError('malformed','invalid heartbeat policy');
    const {interval_seconds: interval, grace_seconds: grace} = heartbeat;
    if (!Number.isInteger(interval) || !Number.isInteger(grace) || interval < 30 || interval > 86400 || grace < interval || grace > 31536000 || epoch(value.expires) > epoch(value.issued) + grace) throw new LicenseboxError('malformed','invalid heartbeat policy or contact deadline');
  }
  if (now >= epoch(value.expires) && !allowExpired) throw new LicenseboxError('expired');
  return value;
}

export class Client {
  private readonly product: string;
  private readonly keys: Record<string, string>;
  private readonly version: string;
  private readonly server: string;
  private readonly directory: string;
  private readonly clock: () => number;
  private host?: string;
  private checked?: Lease;
  private queue: Promise<void> = Promise.resolve();
  constructor(private readonly config: Config) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(config.product) || !Object.keys(config.keys).length) throw new TypeError('a product ID and trusted public keys are required');
    for (const key of Object.values(config.keys)) decode(key, 32);
    const server = new URL(config.server ?? 'https://licensebox.dev');
    if (server.username || server.password || server.search || server.hash || server.protocol !== 'https:' && !(server.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(server.hostname))) throw new TypeError('server must use HTTPS (HTTP is allowed only on loopback)');
    this.product = config.product; this.keys = {...config.keys}; this.version = config.version ?? ''; this.server = server.href.replace(/\/$/, '');
    const base = platform() === 'win32' ? process.env.APPDATA : platform() === 'darwin' ? join(homedir(), 'Library', 'Application Support') : process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config');
    if (!config.directory && !base) throw new LicenseboxError('io_error', 'user configuration directory is unavailable');
    this.directory = config.directory ?? join(base!, 'licensebox', this.product);
    this.clock = config.clock ?? (() => Date.now()/1000);
  }
  private locked<T>(work: () => Promise<T> | T): Promise<T> {
    const run = this.queue.then(work);
    this.queue = run.then(() => {}, () => {});
    return run;
  }
  private binding(): string {
    if (!this.host) {
      const value = this.config.machineBinding ? this.config.machineBinding() : nativeBinding(this.product);
      if (!validBinding(value)) throw new LicenseboxError('identity_unavailable');
      this.host = value;
    }
    return this.host;
  }
  private read(name: string): string {
    try { return readFileSync(join(this.directory, name), 'utf8').trim(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return ''; throw new LicenseboxError('io_error', 'cannot read licence state'); }
  }
  private write(name: string, text: string): void {
    mkdirSync(this.directory, {recursive: true, mode: 0o700});
    const temporary = join(this.directory, `.tmp-${randomBytes(16).toString('hex')}`);
    try { writeFileSync(temporary, `${text}\n`, {mode: 0o600, flag: 'wx'}); chmodSync(temporary, 0o600); renameSync(temporary, join(this.directory, name)); }
    finally { if (existsSync(temporary)) unlinkSync(temporary); }
  }
  private remove(name: string): void {
    try { unlinkSync(join(this.directory, name)); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  private now(): number {
    const seen = this.read('seen');
    const value = Math.max(this.clock(), seen ? epoch(seen) : -Infinity);
    this.write('seen', new Date(value*1000).toISOString());
    return value;
  }
  private async key(): Promise<KeyObject> {
    mkdirSync(this.directory, {recursive:true, mode:0o700});
    for (let attempt=0; attempt<40; attempt++) {
      const seed = this.read('install.key');
      if (seed) {
        try { return createPrivateKey({key:Buffer.concat([privatePrefix, decode(seed,32)]), format:'der', type:'pkcs8'}); } catch { /* another process may be writing */ }
      }
      let descriptor: number;
      try { descriptor = openSync(join(this.directory,'install.key'),'wx',0o600); }
      catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') { await delay(25); continue; } throw error; }
      const raw = randomBytes(32);
      try { writeFileSync(descriptor, `${encode(raw)}\n`); } finally { closeSync(descriptor); }
      return createPrivateKey({key:Buffer.concat([privatePrefix,raw]), format:'der', type:'pkcs8'});
    }
    throw new LicenseboxError('io_error','installation key is damaged or being written by another process');
  }
  private publicKey(key: KeyObject): string { return encode((createPublicKey(key).export({format:'der',type:'spki'}) as Buffer).subarray(-32)); }
  private existingKey(): KeyObject {
    const seed = this.read('install.key');
    if (!seed) throw new LicenseboxError('not_signed_in','the installation key is unavailable; explicitly sign in');
    try { return createPrivateKey({key:Buffer.concat([privatePrefix,decode(seed,32)]),format:'der',type:'pkcs8'}); }
    catch { throw new LicenseboxError('io_error','the installation key is damaged; explicitly sign in'); }
  }
  private async own(value: Lease, key?: KeyObject): Promise<void> {
    if (value.binding !== this.binding() || value.machine !== this.publicKey(key ?? await this.key())) throw new PolicyError('machine_changed','these credentials belong to another machine; explicitly sign in to activate here');
  }
  private denial(): void {
    const saved = this.read('policy-denial');
    if (!saved && !existsSync(join(this.directory,'policy-denial'))) return;
    let value: Json;
    try { value = JSON.parse(saved); if (!policies.has(value.code)) throw new Error(); }
    catch { throw new LicenseboxError('io_error','saved policy refusal is damaged; connect to renew'); }
    throw new PolicyError(value.code,value.detail);
  }
  private async post<T = Json>(path: string, value: Json, timeout = 20_000, signal?: AbortSignal): Promise<T> {
    let response: Response;
    let observedStatus = 0;
    const signals = [AbortSignal.timeout(Math.max(1,Math.ceil(timeout)))];
    if (this.config.signal) signals.push(this.config.signal);
    if (signal) signals.push(signal);
    try {
      const requestSignal = AbortSignal.any(signals);
      if (this.config.caBundle && this.server.startsWith('https:')) {
        const ca = readFileSync(this.config.caBundle);
        response = await new Promise<Response>((resolve,reject) => {
          const request = httpsRequest(this.server+path,{method:'POST',headers:{'Content-Type':'application/json'},ca,signal:requestSignal},incoming => {
            observedStatus = incoming.statusCode ?? 0;
            const chunks: Buffer[] = []; let length = 0;
            incoming.on('data',(chunk: Buffer) => {
              length += chunk.length;
              if (length > limit) { incoming.destroy(); reject(new LicenseboxError('protocol_error','server response exceeded size limit',incoming.statusCode)); }
              else chunks.push(chunk);
            });
            incoming.on('error',error => reject(new LicenseboxError(requestSignal.aborted && (signal?.aborted || this.config.signal?.aborted) ? 'cancelled' : 'network_error','cannot read server response',incoming.statusCode)));
            incoming.on('end',() => resolve(new Response([204,205,304].includes(incoming.statusCode ?? 0) ? null : Buffer.concat(chunks),{status:incoming.statusCode ?? 500})));
          });
          request.on('error',reject); request.end(JSON.stringify(value));
        });
      } else {
        response = await fetch(this.server+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(value),redirect:'manual',signal:requestSignal});
      }
    } catch (error) {
      if (error instanceof LicenseboxError) throw error;
      throw new LicenseboxError(this.config.signal?.aborted || signal?.aborted ? 'cancelled' : 'network_error', 'cannot reach the licensing server',observedStatus);
    }
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = []; let length = 0;
    try {
      if (reader) for (;;) {
        const next = await reader.read(); if (next.done) break;
        length += next.value.length;
        if (length > limit) { await reader.cancel(); throw new LicenseboxError('protocol_error','server response exceeded size limit',response.status); }
        chunks.push(next.value);
      }
    } catch (error) { if (error instanceof LicenseboxError) throw error; throw new LicenseboxError(this.config.signal?.aborted || signal?.aborted ? 'cancelled' : 'network_error','cannot read server response',response.status); }
    let answer: any;
    try { answer = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { throw new LicenseboxError(response.status === 200 ? 'protocol_error':'http_error',`HTTP ${response.status}`,response.status); }
    if (response.status !== 200) {
      const code = typeof answer?.error === 'string' ? answer.error : 'http_error';
      const detail = typeof answer?.error_description === 'string' ? answer.error_description : code;
      if (policies.has(code)) { this.write('policy-denial',JSON.stringify({code,detail:detail || code})); throw new PolicyError(code,detail,response.status); }
      if (code === 'revoked') this.forget();
      throw new LicenseboxError(code,detail,response.status);
    }
    return answer as T;
  }
  private async save(token: string, key?: KeyObject): Promise<Lease> {
    const value = verifyLease(token,this.product,this.keys,this.now()); await this.own(value,key);
    this.write('lease',token); this.remove('policy-denial'); return value;
  }
  private async call<T = Json>(kind: string, payload: Json, timeout = 20_000, key?: KeyObject, signal?: AbortSignal): Promise<T> {
    if (!calls.has(kind)) throw new TypeError('unknown signed operation');
    const token = this.read('lease'); await this.own(parse(token).value,key);
    const body = JSON.stringify(payload), at = stamp(this.clock()), binding = this.binding();
    const message = `licensebox ${kind} v2\n${token}\n${binding}\n${at}\n${createHash('sha256').update(body).digest('hex')}`;
    return this.post<T>(`/v1/${kind}`,{lease:token,binding,time:at,payload:body,version:this.version,signature:encode(sign(null,Buffer.from(message),key ?? await this.key()))},timeout,signal);
  }
  private async renew(timeout = 3000, key?: KeyObject, signal?: AbortSignal): Promise<Lease> {
    const sent = this.usage().slice(0,100), response = await this.call('renew',{usage:sent},timeout,key,signal);
    const value = await this.save(response.lease,key); this.usageSent(sent,response.usage === true); return value;
  }
  private async getLease(): Promise<Lease> {
    this.binding(); const now = this.now();
    if (this.checked && now < epoch(this.checked.expires) && !existsSync(join(this.directory,'policy-denial'))) return structuredClone(this.checked);
    const token = this.read('lease'); if (!token) return this.activate(false);
    let kept: Lease;
    try { kept = verifyLease(token,this.product,this.keys,now,true); }
    catch (error) { if (error instanceof LicenseboxError) return this.activate(false); throw error; }
    await this.own(kept);
    try { this.checked = await this.renew(); return structuredClone(this.checked); }
    catch (error) {
      if (!(error instanceof LicenseboxError)) throw error;
      if (error instanceof PolicyError) throw error;
      if (['invalid_lease','terms_changed'].includes(error.code)) return this.activate(false);
      if (error.code === 'revoked' || error.status >= 300 && error.status < 500) throw error;
      this.denial();
      if (error.code === 'network_error' || error.status >= 500) {
        if (now < epoch(kept.expires)) return kept;
        throw new LicenseboxError('offline','the offline lease expired; connect to the internet');
      }
      throw error;
    }
  }
  lease(): Promise<Lease> { return this.locked(() => this.getLease()); }
  require(module: string): Promise<Lease> {
    return this.locked(async () => {
      let value = await this.getLease();
      if (!value.modules.includes(module) && !this.checked) {
        try { value = this.checked = await this.renew(); }
        catch (error) { if (!(error instanceof LicenseboxError) || error instanceof PolicyError || error.code !== 'network_error' && error.status < 500) throw error; }
      }
      if (!value.modules.includes(module)) throw new ModuleError(this.product,module,value.email);
      return structuredClone(value);
    });
  }
  /** Force a silent contact without activation or installation-key replacement. */
  heartbeat(module: string, options: {signal?: AbortSignal} = {}): Promise<HeartbeatResult> {
    return this.locked(async () => {
      if (typeof module !== 'string' || !module) throw new LicenseboxError('invalid_argument','a nonempty module is required');
      if (options.signal?.aborted) throw new LicenseboxError('cancelled');
      const token = this.read('lease');
      if (!token) throw new LicenseboxError('not_signed_in');
      const kept = verifyLease(token,this.product,this.keys,this.now(),true), key = this.existingKey();
      await this.own(kept,key);
      let value: Lease, online: boolean;
      try { value = await this.renew(3000,key,options.signal); online = true; }
      catch (error) {
        if (!(error instanceof LicenseboxError) || error instanceof PolicyError || ['revoked','invalid_lease','terms_changed'].includes(error.code) || error.status >= 300 && error.status < 500) throw error;
        if (error.code !== 'network_error' && error.status < 500) throw error;
        this.denial();
        if (this.now() >= epoch(kept.expires)) throw new LicenseboxError('offline','the offline lease expired; connect to the internet');
        value = kept; online = false;
      }
      this.checked = value;
      if (!value.modules.includes(module)) throw new ModuleError(this.product,module,value.email);
      return {lease:structuredClone(value),online};
    });
  }
  /** Explicit monitoring; construction and require() never start timers. */
  async watch(module: string, options: WatchOptions = {}): Promise<HeartbeatMonitor> {
    validateInterval(options.intervalSeconds);
    options = {...options,signal: this.config.signal && options.signal ? AbortSignal.any([this.config.signal,options.signal]) : options.signal ?? this.config.signal};
    if (options.signal?.aborted) throw new LicenseboxError('cancelled');
    const first = await this.heartbeat(module,{signal:options.signal});
    return new Monitor(this,module,first,this.now(),() => Math.max(this.clock(),this.read('seen') ? epoch(this.read('seen')) : -Infinity),options);
  }
  status(): Promise<Lease> {
    return this.locked(async () => {
      this.denial(); const token = this.read('lease'); if (!token) throw new LicenseboxError('not_signed_in');
      const value = verifyLease(token,this.product,this.keys,this.now(),true); await this.own(value);
      if (this.now() >= epoch(value.expires)) throw new LicenseboxError('expired'); return value;
    });
  }
  signIn(timeoutSeconds?: number): Promise<Lease> { return this.locked(() => this.activate(true,timeoutSeconds)); }
  private async rotate(): Promise<void> { this.write('install.key',encode(randomBytes(32))); this.forget(); }
  private async activate(explicit: boolean, timeoutSeconds?: number, rotated = false): Promise<Lease> {
    const binding = this.binding(); let old: Lease | undefined;
    try { old = parse(this.read('lease')).value; } catch { /* no readable old lease */ }
    if (old && validBinding(old.binding) && old.binding !== binding) {
      if (!explicit) throw new PolicyError('machine_changed','explicitly sign in to activate this machine');
      await this.rotate(); rotated = true;
    }
    const key = await this.key(), at = stamp(this.clock());
    let device: Json;
    try { device = await this.post('/v1/device',{product:this.product,machine:this.publicKey(key),binding,os:platform() === 'win32'?'windows':platform(),arch:arch()==='x64'?'amd64':arch(),version:this.version,time:at,signature:encode(sign(null,Buffer.from(`licensebox device v2\n${this.product}\n${binding}\n${at}`),key))}); }
    catch (error) {
      if (explicit && !rotated && error instanceof PolicyError && error.code === 'machine_changed') { await this.rotate(); return this.activate(false,timeoutSeconds,true); }
      throw error;
    }
    const link = device.verification_uri_complete ?? device.verification_uri;
    if (this.config.onSignIn) await this.config.onSignIn(link,device.user_code);
    else console.error(`${this.product} needs a one-time sign-in.\nOpen ${link} and enter ${device.user_code}`);
    let interval = device.interval_ms > 0 ? device.interval_ms : Math.max(device.interval ?? 1,1)*1000;
    const deadline = Date.now()+Math.min(device.expires_in,timeoutSeconds ?? device.expires_in)*1000;
    while (Date.now() < deadline) {
      try { await delay(Math.min(interval,deadline-Date.now()),undefined,{signal:this.config.signal}); }
      catch { throw new LicenseboxError('cancelled'); }
      if (Date.now() >= deadline) break;
      const at = stamp(this.clock());
      try {
        const response = await this.post('/v1/token',{device_code:device.device_code,binding,time:at,signature:encode(sign(null,Buffer.from(`licensebox token v2\n${device.device_code}\n${binding}\n${at}`),key))},Math.min(20_000,deadline-Date.now()));
        const value = await this.save(response.lease);
        if (old && old.user !== value.user) this.remove('usage.json');
        this.usageSent([],response.usage === true); this.checked = value; return structuredClone(value);
      } catch (error) {
        if (!(error instanceof LicenseboxError)) throw error;
        if (error.code === 'authorization_pending') continue;
        if (error.code === 'slow_down') { interval += 5000; continue; }
        if (error.code === 'network_error' || error.status >= 500) continue;
        if (error.code === 'access_denied') throw new LicenseboxError('denied');
        if (error.code === 'expired_token') throw new LicenseboxError('sign_in_expired');
        throw error;
      }
    }
    throw new LicenseboxError('sign_in_expired');
  }
  private forget(): void { this.checked = undefined; for (const name of ['lease','usage.json','usage-on','policy-denial']) this.remove(name); }
  logout(): Promise<void> { return this.locked(() => this.forget()); }
  modules(): Promise<Module[]> { return this.locked(async () => { await this.getLease(); return this.call<Module[]>('modules',{}); }); }
  requestAccess(modules: string[], note: string): Promise<AccessRequest> { return this.locked(async () => { await this.getLease(); return this.call<AccessRequest>('request',{modules,note}); }); }
  requests(): Promise<AccessRequest[]> { return this.locked(async () => { await this.getLease(); return this.call<AccessRequest[]>('requests',{}); }); }
  accessLink(): Promise<string> { return this.locked(async () => { await this.getLease(); return (await this.call('access-link',{})).url; }); }
  private usage(): Json[] { const value = this.read('usage.json'); return value ? JSON.parse(value) : []; }
  private usageSent(sent: Json[], enabled: boolean): void {
    this.write('usage-on',enabled?'on':'off');
    if (sent.length) this.write('usage.json',JSON.stringify(this.usage().filter(x => !sent.some(s => s.id === x.id && s.ok === x.ok && s.failed === x.failed && s.ms === x.ms))));
  }
  /** Count fixed command names, never paths, arguments or user data. */
  record(command: string, ok: boolean, elapsedSeconds: number): Promise<void> {
    return this.locked(() => {
      if (this.read('usage-on') !== 'on' || !command || Buffer.byteLength(command)>64 || !Number.isFinite(elapsedSeconds) || elapsedSeconds<0) return;
      const queued = this.usage();
      const group = {day:stamp(this.clock()).slice(0,10),command,version:this.version.slice(0,64),os:`${platform()==='win32'?'windows':platform()}/${arch()==='x64'?'amd64':arch()}`};
      let item = queued.find(x => Object.entries(group).every(([key,value]) => x[key]===value));
      if (!item) { item = {...group,id:randomBytes(16).toString('hex'),ok:0,failed:0,ms:0}; queued.push(item); }
      item[ok?'ok':'failed']++; item.ms += Math.floor(elapsedSeconds*1000);
      this.write('usage.json',JSON.stringify(queued.slice(-1000)));
    });
  }
}


export interface HeartbeatResult { lease: Lease; online: boolean }
export interface WatchOptions {
  /** Seconds; may shorten the server interval (default 300), never lengthen it. */
  intervalSeconds?: number;
  signal?: AbortSignal;
  /** Notification only. Throwing/rejected callbacks are contained. */
  onStop?: (error?: LicenseboxError) => void | Promise<void>;
}
export interface HeartbeatMonitor {
  /** Pass this signal to protected work and stop at safe cancellation points. */
  readonly signal: AbortSignal;
  readonly latest: HeartbeatResult;
  readonly done: Promise<LicenseboxError | undefined>;
  stop(): void;
}
function validateInterval(interval?: number): void {
  if (interval !== undefined && (!Number.isFinite(interval) || interval <= 0)) throw new TypeError('intervalSeconds must be positive');
}
class Monitor implements HeartbeatMonitor {
  private readonly controller = new AbortController();
  private readonly renewal = new AbortController();
  readonly signal = this.controller.signal;
  readonly done: Promise<LicenseboxError | undefined>;
  private resolve!: (error?: LicenseboxError) => void;
  private result: HeartbeatResult;
  private deadline: number;
  private expires: number;
  private timer?: ReturnType<typeof setTimeout>;
  private watchdog?: ReturnType<typeof setTimeout>;
  private readonly cancelled = () => this.finish(new LicenseboxError('cancelled'));
  constructor(private readonly client: Client, private readonly module: string, first: HeartbeatResult,
              now: number, private readonly clock: () => number, private readonly options: WatchOptions) {
    this.result = structuredClone(first);
    this.expires = epoch(first.lease.expires);
    this.deadline = performance.now() + Math.max(0,this.expires - now)*1000;
    this.done = new Promise(resolve => { this.resolve = resolve; });
    if (options.signal?.aborted) { this.cancelled(); return; }
    options.signal?.addEventListener('abort',this.cancelled,{once:true});
    this.armWatchdog();
    this.schedule();
  }
  get latest(): HeartbeatResult { return structuredClone(this.result); }
  stop(): void { this.finish(); }
  private expired(): boolean { return performance.now() >= this.deadline; }
  private finish(error?: LicenseboxError): void {
    if (this.signal.aborted) return;
    clearTimeout(this.timer); clearTimeout(this.watchdog);
    this.options.signal?.removeEventListener('abort',this.cancelled);
    this.renewal.abort();
    this.controller.abort(error);
    this.resolve(error);
    // Never hold the watchdog or consumer notification hostage to a callback.
    if (this.options.onStop) Promise.resolve().then(() => this.options.onStop!(error)).catch(() => {});
  }
  private armWatchdog(): void {
    clearTimeout(this.watchdog);
    if (this.signal.aborted) return;
    if (this.expired()) { this.finish(new LicenseboxError('expired','the signed heartbeat deadline expired')); return; }
    this.watchdog = setTimeout(() => this.armWatchdog(),Math.max(1,Math.min(100,this.deadline-performance.now())));
  }
  private schedule(): void {
    if (this.signal.aborted) return;
    const interval = Math.min(this.options.intervalSeconds ?? Infinity,this.result.lease.heartbeat?.interval_seconds ?? 300);
    this.timer = setTimeout(() => { void this.check(); },Math.min(2_147_483_647,interval*1000));
  }
  private async check(): Promise<void> {
    try {
      const result = await this.client.heartbeat(this.module,{signal:this.renewal.signal});
      if (this.signal.aborted) return;
      if (this.expired()) { this.finish(new LicenseboxError('expired','the signed heartbeat deadline expired')); return; }
      this.result = structuredClone(result);
      if (result.online) {
        this.expires = epoch(result.lease.expires);
        this.deadline = performance.now() + Math.max(0,this.expires-this.clock())*1000;
      }
      this.armWatchdog(); this.schedule();
    } catch (error) {
      this.finish(error instanceof LicenseboxError ? error : new LicenseboxError('monitor_error','heartbeat check failed'));
    }
  }
}
