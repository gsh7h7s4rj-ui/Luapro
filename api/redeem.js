const Redis = require('ioredis');

const redis = new Redis(process.env.REDIS_URL, {
    tls: process.env.REDIS_URL && process.env.REDIS_URL.startsWith('rediss://') ? {} : undefined,
    maxRetriesPerRequest: 3,
    lazyConnect: false
});

const GIFT_KV   = 'veil_gift_codes';
const REDEEM_KV = 'veil_gift_redemptions';
const KEY_KV    = 'veil_api_keys';
const ADMIN_KEY = 'stdlibisthefuckinggoat';

function normalizeCode(raw) {
    return String(raw || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function makeCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 12; i++) {
        if (i > 0 && i % 4 === 0) code += '-';
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

async function loadGiftCodes() {
    try {
        const raw = await redis.get(GIFT_KV);
        return raw ? JSON.parse(raw) : [];
    } catch(e) { return []; }
}

async function saveGiftCodes(codes) {
    await redis.set(GIFT_KV, JSON.stringify(codes));
}

async function loadKeys() {
    try {
        const raw = await redis.get(KEY_KV);
        return raw ? JSON.parse(raw) : [];
    } catch(e) { return []; }
}

async function saveKeys(keys) {
    await redis.set(KEY_KV, JSON.stringify(keys));
}

module.exports = async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.status(200).end();

    let body = req.body || {};
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch(e) { body = {}; } }
    const action = String(body.action || 'redeem');

    try {
        if (action === 'list-codes') {
            const adminKey = String(body.adminKey || '');
            if (adminKey !== ADMIN_KEY) return res.status(401).json({ ok: false, error: 'Unauthorized' });
            const codes = await loadGiftCodes();
            return res.json({ ok: true, codes });
        }

        if (action === 'generate') {
            const adminKey = String(body.adminKey || '');
            if (adminKey !== ADMIN_KEY) return res.status(401).json({ ok: false, error: 'Unauthorized' });

            const amount = Math.max(1, Math.min(1000, parseInt(body.amount || 1)));
            const value  = Math.max(1, Math.min(1000000, parseInt(body.value || 100)));
            const expiry = body.expiry ? new Date(body.expiry).toISOString() : null;

            const codes = await loadGiftCodes();
            const generated = [];
            for (let i = 0; i < amount; i++) {
                let code = makeCode();
                let tries = 0;
                while (tries < 12 && codes.some(c => normalizeCode(c.code) === normalizeCode(code))) {
                    code = makeCode();
                    tries++;
                }
                codes.push({ code, value, used: false, expiry });
                generated.push(code);
            }
            await saveGiftCodes(codes);
            return res.json({ ok: true, codes: generated, value });
        }

        if (action === 'redeem') {
            const raw = body.code;
            const code = normalizeCode(raw);
            if (!code) return res.status(400).json({ ok: false, error: 'Missing code' });

            const apiKey  = String(body.apiKey  || '').trim();

            const giftCodes = await loadGiftCodes();
            const idx = giftCodes.findIndex(c => normalizeCode(c.code) === code);
            if (idx === -1) return res.status(404).json({ ok: false, error: 'Invalid code' });

            const gc = giftCodes[idx];
            if (gc.used) return res.status(409).json({ ok: false, error: 'Code already used' });
            if (gc.expiry && new Date(gc.expiry) < new Date()) return res.status(410).json({ ok: false, error: 'Code expired' });

            let newLimit = null;
            if (apiKey) {
                const keys = await loadKeys();
                const keyIdx = keys.findIndex(k => k.key.trim() === apiKey);
                
                if (keyIdx === -1) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
                
                const user = keys[keyIdx];
                if (!user.active) return res.status(401).json({ ok: false, error: 'Account disabled' });
                if (user.expiry && new Date(user.expiry) < new Date()) return res.status(401).json({ ok: false, error: 'Account expired' });

                user.limit = (user.limit || 0) + gc.value;
                newLimit = user.limit;
                keys[keyIdx] = user;
                await saveKeys(keys);
            }

            giftCodes[idx].used = true;
            giftCodes[idx].used_at = new Date().toISOString();
            await saveGiftCodes(giftCodes);

            let redemptions = [];
            try {
                const rawR = await redis.get(REDEEM_KV);
                if (rawR) redemptions = JSON.parse(rawR);
            } catch(e) {}
            redemptions.push({ code, apiKey, ip: req.headers['x-forwarded-for'] || req.ip, at: new Date().toISOString() });
            await redis.set(REDEEM_KV, JSON.stringify(redemptions.slice(-200)));

            return res.json({ ok: true, credits: gc.value, newLimit, message: 'Redeemed' });
        }

        return res.status(400).json({ ok: false, error: 'Invalid action' });
    } catch(err) {
        console.error('redeem.js error:', err);
        return res.status(500).json({ ok: false, error: 'Server error: ' + err.message });
    }
};