'use strict';

const fs = require('fs');
const path = require('path');
const Redis = require('ioredis');
const { luaToProgram, compile, buildLuaRuntime, makeV, antiTamper } = require('../vm.js');

const redis = new Redis(process.env.REDIS_URL, {
    tls: process.env.REDIS_URL && process.env.REDIS_URL.startsWith('rediss://') ? {} : undefined,
    maxRetriesPerRequest: 3,
});

const KV_KEY = 'veil_api_keys';

function keyStatus(k) {
    if (!k.active) return 'inactive';
    if (k.expiry && new Date(k.expiry) < new Date()) return 'expired';
    if (k.used >= k.limit) return 'exhausted';
    return 'active';
}

async function validateAndIncrement(key) {
    let keys = [];
    try {
        const raw = await redis.get(KV_KEY);
        if (raw) keys = JSON.parse(raw);
        if (!Array.isArray(keys)) return { valid: false, reason: 'no_keys' };
    } catch(e) { return { valid: false, reason: 'db_error' }; }
    
    const idx = keys.findIndex(k => k.key.trim() === (key || '').trim());
    
    if (idx === -1) return { valid: false, reason: 'not_found' };
    const status = keyStatus(keys[idx]);
    if (status !== 'active') return { valid: false, reason: status };
    
    keys[idx].used++;
    await redis.set(KV_KEY, JSON.stringify(keys));
    return { valid: true };
}

function randInt(lo, hi) { return Math.floor(Math.random() * (hi - lo + 1)) + lo; }

function heavyNum(n, V) {
  n = n >>> 0;
  const roll = randInt(0, 5);
  if (roll === 0 && n > 1) {
    const a = randInt(1, n - 1);
    return `(0x${a.toString(16)}+0x${(n - a).toString(16)})`;
  }
  if (roll === 1) {
    const m = randInt(1, 0xff);
    return `bit32.bxor(0x${((n ^ m) >>> 0).toString(16)},0x${m.toString(16)})`;
  }
  if (roll === 2) {
    return `bit32.bor(0x${n.toString(16)},0x0)`;
  }
  if (roll === 3) {
    return `bit32.band(0x${n.toString(16)},0xFFFFFFFF)`;
  }
  if (roll === 4) {
    return `(0x${n.toString(16)}+0x0)*0x1`;
  }
  return `0x${n.toString(16)}`;
}

function stripLuaComments(src) {
    let result = '';
    let i = 0;
    const len = src.length;
    while (i < len) {
        if (src[i] === '-' && src[i+1] === '-' && src[i+2] === '[' && src[i+3] === '[') {
            i += 4;
            while (i < len) {
                if (src[i] === ']' && src[i+1] === ']') { i += 2; break; }
                i++;
            }
            continue;
        }
        if (src[i] === '-' && src[i+1] === '-') {
            while (i < len && src[i] !== '\n') i++;
            continue;
        }
        if (src[i] === '"' || src[i] === "'") {
            const q = src[i];
            result += src[i++];
            while (i < len) {
                if (src[i] === '\\') { result += src[i] + src[i+1]; i += 2; continue; }
                if (src[i] === q) { result += src[i++]; break; }
                result += src[i++];
            }
            continue;
        }
        if (src[i] === '[' && src[i+1] === '[') {
            result += src[i++];
            result += src[i++];
            while (i < len) {
                if (src[i] === ']' && src[i+1] === ']') { result += ']]'; i += 2; break; }
                result += src[i++];
            }
            continue;
        }
        result += src[i++];
    }
    return result;
}

function buildAntiTamperPrelude(V, opts) {
  return "";
}

function compileVM(luaSource, opts = {}) {
  const key = opts.key || Array.from({ length: 24 }, () =>
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[randInt(0, 61)]
  ).join('');
  const V = makeV(); 

  let sourceToCompile = luaSource;
  if (opts.antiTamper !== false) {
    const atLua = buildAntiTamperPrelude(V, { checkFps: opts.checkFps !== false });
    sourceToCompile = antiTamper + '\n' + atLua + '\n' + luaSource;
  }

  const program = luaToProgram(sourceToCompile);
  const { cb1Payload, luaKey, byteMap, strLock } = compile(program, key);
  const vmRuntime = buildLuaRuntime(cb1Payload, luaKey, V, byteMap, strLock);

  return { output: vmRuntime.trim(), key };
}

async function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    const MAX_PAYLOAD_SIZE = 5 * 1024 * 1024;

    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_PAYLOAD_SIZE) {
        reject(new Error('Payload too large. Maximum size is 5MB.'));
        return;
      }
      data += chunk;
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    let raw = req.body;

    if (raw === undefined || raw === null || raw === '') {
        try { raw = await readRawBody(req); } catch(err) { return res.status(400).json({ error: err.message }); }
    }

    let body = raw;
    if (typeof raw === 'string') {
      const trimmed = raw.trim();
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        try { body = JSON.parse(trimmed); } catch { body = { src: raw }; }
      } else {
        body = { src: raw };
      }
    } else if (Buffer.isBuffer(raw)) {
      body = { src: raw.toString('utf8') };
    } else if (typeof raw !== 'object') {
      body = {};
    }

    const src = body.src ?? body.source ?? body.code ?? body.script ?? body.lua ?? body.input ?? body.text;
    const mode = body.mode;
    const apiKey = body.key ?? body.apiKey ?? body.obfKey;
    const { antiTamper: atOpt, checkFps } = body;

    if (!src || typeof src !== 'string' || !src.trim())
        return res.status(400).json({ error: 'No source code provided' });

    const check = await validateAndIncrement(apiKey);
    if (!check.valid)
        return res.status(401).json({ error: 'Invalid or inactive API key', reason: check.reason });

    try {
        const cleanSrc = stripLuaComments(src.trim());
        const vmResult = compileVM(cleanSrc, { key: apiKey, antiTamper: atOpt, checkFps });
        return res.status(200).json({ final: vmResult.output, output: vmResult.output, key: vmResult.key });

    } catch(err) {
        return res.status(500).json({ error: 'Obfuscation failed: ' + err.message });
    }
}

module.exports = handler;
module.exports.obfuscate = compileVM;
module.exports.default = handler;