const Redis = require('ioredis');

const redis = new Redis(process.env.REDIS_URL, {
    tls: process.env.REDIS_URL && process.env.REDIS_URL.startsWith('rediss://') ? {} : undefined,
    maxRetriesPerRequest: 3,
    lazyConnect: false
});

const KV_KEY    = 'veil_api_keys';
const ADMIN_KEY = 'stdlibisthefuckinggoat';

const PLAN_BONUSES = {
    standard: 0,
    creator: 100,
    pro: 200,
    enterprise: 500
};

function today() { return new Date().toISOString().slice(0, 10); }

function keyStatus(k) {
    if (!k.active) return 'inactive';
    if (k.expiry && new Date(k.expiry) < new Date()) return 'expired';
    if (k.used >= k.limit) return 'exhausted';
    return 'active';
}

async function loadKeys() {
    let keys = [];
    try {
        const raw = await redis.get(KV_KEY);
        if (raw) keys = JSON.parse(raw);
        if (!Array.isArray(keys)) keys = [];
    } catch(e) { keys = []; }

    const ai = keys.findIndex(k => k.id === 'k_admin');
    if (ai === -1) {
        keys.unshift({
            id: 'k_admin',
            key: ADMIN_KEY,
            limit: 1000000,
            used: 0,
            expiry: '',
            active: true,
            created: today(),
            plan: 'standard',
            lastBonusDate: null
        });
        await redis.set(KV_KEY, JSON.stringify(keys));
    } else {
        keys[ai].key = ADMIN_KEY;
        keys[ai].active = true;
        if (!keys[ai].plan) keys[ai].plan = 'standard';
        if (keys[ai].lastBonusDate === undefined) keys[ai].lastBonusDate = null;
    }

    let updated = false;
    keys.forEach(k => {
        if (!k.plan) { k.plan = 'standard'; updated = true; }
        if (k.lastBonusDate === undefined) { k.lastBonusDate = null; updated = true; }
    });
    if (updated) await redis.set(KV_KEY, JSON.stringify(keys));

    return keys;
}

async function saveKeys(keys) {
    await redis.set(KV_KEY, JSON.stringify(keys));
}

function applyPlanBonus(key, planOverride) {
    const plan = planOverride || key.plan || 'standard';
    const bonus = PLAN_BONUSES[plan] || 0;
    if (bonus > 0) {
        key.limit = (key.limit || 0) + bonus;
        key.lastBonusDate = today();
    }
}

module.exports = async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.status(200).end();

    let body = req.body || {};
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch(e) { body = {}; } }
    const { action } = body;

    try {
        if (action === 'validate') {
            const { key } = body;
            const keys = await loadKeys();
            const entry = keys.find(k => k.key.trim() === (key||'').trim());
            if (!entry) return res.json({ valid:false, reason:'not_found' });
            const status = keyStatus(entry);
            if (status !== 'active') return res.json({ valid:false, reason:status });
            return res.json({
                valid: true,
                id: entry.id,
                used: entry.used,
                limit: entry.limit,
                expiry: entry.expiry || '',
                plan: entry.plan || 'standard',
                lastBonusDate: entry.lastBonusDate || null,
                isAdmin: entry.id === 'k_admin'
            });
        }

        if (action === 'list') {
            if ((body.adminKey||'').trim() !== ADMIN_KEY) return res.status(403).json({ error:'Forbidden' });
            const keys = await loadKeys();
            return res.json({
                keys: keys.map(k => ({
                    ...k,
                    status: keyStatus(k),
                    plan: k.plan || 'standard',
                    lastBonusDate: k.lastBonusDate || null
                }))
            });
        }

        if (action === 'add') {
            if ((body.adminKey||'').trim() !== ADMIN_KEY) return res.status(403).json({ error:'Forbidden' });
            const { key, limit, expiry, plan } = body;
            if (!key) return res.status(400).json({ error:'Key required' });
            const keys = await loadKeys();
            const newPlan = (plan || 'standard').trim().toLowerCase();
            const entry = {
                id: 'k_'+Date.now(),
                key: key.trim(),
                limit: Math.max(1, Math.min(1000000, parseInt(limit) || 100)),
                used: 0,
                expiry: expiry || '',
                active: true,
                created: today(),
                plan: newPlan,
                lastBonusDate: null
            };
            if (PLAN_BONUSES[newPlan] > 0) {
                applyPlanBonus(entry);
            }
            keys.push(entry);
            await saveKeys(keys);
            return res.json({ success:true, entry:{ ...entry, status:'active' } });
        }

        if (action === 'generate') {
            if ((body.adminKey||'').trim() !== ADMIN_KEY) return res.status(403).json({ error:'Forbidden' });
            const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            let genKey = '';
            for (let i = 0; i < 52; i++) {
                genKey += chars[Math.floor(Math.random() * chars.length)]; 
            }
            const keys = await loadKeys();
            const newPlan = (body.plan || 'standard').trim().toLowerCase();
            const entry = {
                id: 'k_'+Date.now(),
                key: genKey,
                limit: Math.max(1, Math.min(1000000, parseInt(body.limit) || 100)),
                used: 0,
                expiry: body.expiry || '',
                active: true,
                created: today(),
                plan: newPlan,
                lastBonusDate: null
            };
            if (PLAN_BONUSES[newPlan] > 0) {
                applyPlanBonus(entry);
            }
            keys.push(entry);
            await saveKeys(keys);
            return res.json({ success:true, entry:{ ...entry, status:'active' } });
        }

        if (action === 'toggle') {
            if ((body.adminKey||'').trim() !== ADMIN_KEY) return res.status(403).json({ error:'Forbidden' });
            const keys = await loadKeys();
            const idx = keys.findIndex(k => k.id === body.id);
            if (idx === -1) return res.status(404).json({ error:'Not found' });
            if (keys[idx].id === 'k_admin') return res.status(400).json({ error:'Cannot disable admin' });
            keys[idx].active = !keys[idx].active;
            await saveKeys(keys);
            return res.json({ success:true, active:keys[idx].active });
        }

        if (action === 'reset') {
            if ((body.adminKey||'').trim() !== ADMIN_KEY) return res.status(403).json({ error:'Forbidden' });
            const keys = await loadKeys();
            const idx = keys.findIndex(k => k.id === body.id);
            if (idx === -1) return res.status(404).json({ error:'Not found' });
            keys[idx].used = 0;
            await saveKeys(keys);
            return res.json({ success:true });
        }

        if (action === 'delete') {
            if ((body.adminKey||'').trim() !== ADMIN_KEY) return res.status(403).json({ error:'Forbidden' });
            if (body.id === 'k_admin') return res.status(400).json({ error:'Cannot delete admin' });
            const keys = await loadKeys();
            await saveKeys(keys.filter(k => k.id !== body.id));
            return res.json({ success:true });
        }
        if (action === 'updateUsage') {
            const { key, used } = body;
            if (!key) return res.status(400).json({ error:'Key required' });
            const keys = await loadKeys();
            const idx = keys.findIndex(k => k.key.trim() === key.trim());
            if (idx === -1) return res.status(404).json({ error:'Key not found' });
            keys[idx].used = Math.max(0, parseInt(used) || 0);
            await saveKeys(keys);
            return res.json({ success:true, used: keys[idx].used });
        }
        if (action === 'changePlan') {
            if ((body.adminKey||'').trim() !== ADMIN_KEY) return res.status(403).json({ error:'Forbidden' });
            const { id, plan } = body;
            const allowed = ['standard', 'creator', 'pro', 'enterprise'];
            if (!allowed.includes(plan)) return res.status(400).json({ error:'Invalid plan' });
            const keys = await loadKeys();
            const idx = keys.findIndex(k => k.id === id);
            if (idx === -1) return res.status(404).json({ error:'Not found' });
            const key = keys[idx];
            const newPlan = plan;
            if (PLAN_BONUSES[newPlan] > 0) {
                applyPlanBonus(key, newPlan);
            } else {
                key.lastBonusDate = today();
            }
            key.plan = newPlan;
            await saveKeys(keys);
            return res.json({ success:true, plan: key.plan, limit: key.limit, lastBonusDate: key.lastBonusDate });
        }
        
        if (action === 'resetCooldown') {
            if ((body.adminKey||'').trim() !== ADMIN_KEY) return res.status(403).json({ error:'Forbidden' });
            const { id } = body;
            const keys = await loadKeys();
            const idx = keys.findIndex(k => k.id === id);
            if (idx === -1) return res.status(404).json({ error:'Not found' });
            const key = keys[idx];
            const plan = key.plan || 'standard';
            if (PLAN_BONUSES[plan] > 0) {
                applyPlanBonus(key);
            } else {
                key.lastBonusDate = today();
            }
            await saveKeys(keys);
            return res.json({ success:true, limit: key.limit, lastBonusDate: key.lastBonusDate });
        }

        return res.status(400).json({ error:'Unknown action: ' + action });
    } catch(err) {
        console.error('keys.js error:', err);
        return res.status(500).json({ error:'Server error: ' + err.message });
    }
};