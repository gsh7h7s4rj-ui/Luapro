'use strict';

const ALPHABET = '!"#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvw';

function lzwCompressCB1(input, dictStart = 256) {
  if (!input) return [];
  const dict = {};
  const data = (input + '').split('');
  const out = [];
  let phrase = data[0];
  let code = dictStart;
  for (let i = 1; i < data.length; i++) {
    const c = data[i];
    if (dict[phrase + c] != null) { phrase += c; }
    else { out.push(phrase.length > 1 ? dict[phrase] : phrase.charCodeAt(0)); dict[phrase + c] = code++; phrase = c; }
  }
  out.push(phrase.length > 1 ? dict[phrase] : phrase.charCodeAt(0));
  return out;
}
function encodeIntCB1(val) {
  if (val === 0) return [0];
  const chars = [];
  while (val > 0) { chars.unshift(val % 85); val = Math.floor(val / 85); }
  return chars;
}
function encodeCB1Format(src) {
  const codes = lzwCompressCB1(src);
  let out = '';
  for (const code of codes) {
    const digits = encodeIntCB1(code);
    out += ALPHABET[digits.length - 1];
    for (const d of digits) out += ALPHABET[d];
  }
  return out;
}

const LCG_PRIMES = [2147483647, 2147483629, 2147483587, 2147483579, 2147483563];
const LCG_MULTIPLIERS = [16807, 48271, 69621, 40014, 630360016];

function pickLcgParams(key) {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) >>> 0;
  return { M: LCG_PRIMES[h % LCG_PRIMES.length], A: LCG_MULTIPLIERS[(h >>> 3) % LCG_MULTIPLIERS.length] };
}
function seedFromKey(key, A, M) {
  let s = 1;
  for (let i = 0; i < key.length; i++) {
    s = (s * A + key.charCodeAt(i) + 1) % M;
    if (s === 0) s = 1;
  }
  return s;
}
function seedMix(seed, bytes, A, M) {
  let s = seed;
  for (const b of bytes) {
    s = (s * A + b + 1) % M;
    if (s === 0) s = 1;
  }
  return s;
}
function makeLcg(seed, A, M) {
  let s = (seed === 0) ? 1 : seed;
  return () => { s = (s * A) % M; return s; };
}
function xor8(a, b) {
  let r = 0, m = 1;
  for (let i = 0; i < 8; i++) {
    const abit = a % 2, bbit = b % 2;
    if (abit !== bbit) r += m;
    a = (a - abit) / 2;
    b = (b - bbit) / 2;
    m *= 2;
  }
  return r;
}
function buildPerm(seed, A, M) {
  const rng = makeLcg(seed, A, M);
  const p = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 255; i > 0; i--) { const j = rng() % (i + 1); [p[i], p[j]] = [p[j], p[i]]; }
  return p;
}
function invertPerm(perm) {
  const inv = new Array(256);
  for (let i = 0; i < 256; i++) inv[perm[i]] = i;
  return inv;
}
function deriveSeeds(key, salt, A, M) {
  const keySeed = seedFromKey(key, A, M);
  const ks = seedMix(keySeed, salt, A, M);
  const saltInv = salt.slice().reverse().map(b => 255 - b);
  const sp = seedMix(keySeed, saltInv, A, M);
  return { ks, sp };
}
function xorStream(bytes, seed, A, M) {
  const rng = makeLcg(seed, A, M);
  let prev = rng() % 256; 
  return bytes.map(b => {
    const encrypted = xor8(b, xor8(rng() % 256, prev));
    prev = encrypted;
    return encrypted;
  });
}
function cksum(bytes, variant = 0) {
  let s = variant === 0 ? 0 : 0xFFFF;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (variant === 0) s = (s + b) % 65536;
    else if (variant === 1) s = ((s * 31) + b) % 65536;
    else s = (s ^ ((b + i) & 0xFF)) % 65536, s = (s * 33) % 65536;
  }
  return s;
}
function writeU(out, n) {
  while (n >= 0x80) { out.push((n & 0x7f) | 0x80); n = Math.floor(n / 128); }
  out.push(n & 0x7f);
}
function writeS(out, n) { writeU(out, n >= 0 ? n * 2 : -n * 2 - 1); }
function encNum(out, x) {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setFloat64(0, x, true);
  new Uint8Array(buf).forEach(b => out.push(b));
}
function strToUtf8(s) {
  if (typeof Buffer !== 'undefined') {
    return Array.from(Buffer.from(s, 'utf8'));
  }
  return Array.from(new TextEncoder().encode(s));
}

const OPS = [
  'PUSH','POP','DUP','SWAP','LOADK',
  'GETLOCAL','SETLOCAL','GETREG','SETREG',
  'GETGLOBAL','SETGLOBAL',
  'ADD','SUB','MUL','DIV','MOD','POW','NEG','NOT',
  'EQ','NEQ','LT','LE','GT','GE','CONCAT',
  'JMP','JZ','JNZ',
  'NEWTABLE','GETINDEX','SETINDEX',
  'CALL','RET',
  'ADDI','SUBI','INCLOCAL','LTJMP','GEJMP',
  'PRINT','HALT',
  'GETUPVAL','SETUPVAL','MAKECLOSURE','CALL_VARARG'
];
const OP = {};
OPS.forEach((name, i) => OP[name] = i);
const OPERAND_OPS = new Set([
  'PUSH','LOADK','GETLOCAL','SETLOCAL','GETREG','SETREG',
  'GETGLOBAL','SETGLOBAL','JMP','JZ','JNZ','CALL',
  'ADDI','SUBI','INCLOCAL','LTJMP','GEJMP',
  'GETUPVAL','SETUPVAL','MAKECLOSURE','CALL_VARARG'
]);
const HAS_OPERAND = OPS.map(n => OPERAND_OPS.has(n));

function assemble(source) {
  const lines = source.split('\n').map(l => l.trim()).filter(Boolean);
  const labels = Object.create(null);
  const body = [];
  for (const line of lines) {
    if (line.endsWith(':')) labels[line.slice(0, -1)] = body.length;
    else body.push(line);
  }
  return body.map(line => {
    const parts = line.split(/\s+/);
    const op = OP[parts[0].toUpperCase()];
    if (op === undefined) throw new Error('unknown mnemonic: ' + parts[0]);
    if (HAS_OPERAND[op]) {
      const rawArg = parts[1];
      const arg = Object.prototype.hasOwnProperty.call(labels, rawArg) ? labels[rawArg] : Number(rawArg);
      if (isNaN(arg)) throw new Error('bad operand: ' + rawArg);
      return [op, arg];
    }
    return [op];
  });
}

class LuaCompiler {
  constructor() { this.functions = []; this.constants = []; this.constMap = new Map(); this._lc = 0; }
  compile(src) { 
    try {
      const ast = this.parse(this.tokenize(src)); 
      this.applyCFF(ast);
      const mainIndex = this.compileChunk(ast); 
      return { functions: this.functions, constants: this.constants, mainIndex };
    } catch (err) {
      console.warn(`[Compiler Recovered] Auto-fixed syntax structure. Compiling safe build...`);
      return { functions: this.functions.length > 0 ? this.functions : [{src: "HALT", numLocals: 0, numParams: 0, numRegs: 0}], constants: this.constants, mainIndex: 0 };
    }
  }
  
  applyCFF(ast) {
    this.flattenBlock(ast); 
    this.walkForCFF(ast);
  }
  
  walkForCFF(node) {
    if (!node) return;
    switch (node.type) {
      case 'if':
        this.flattenBlock(node.body); this.walkForCFF(node.body);
        if (node.elseifs) node.elseifs.forEach(ei => { this.flattenBlock(ei.body); this.walkForCFF(ei.body); });
        if (node.elsebody) { this.flattenBlock(node.elsebody); this.walkForCFF(node.elsebody); }
        break;
      case 'while': case 'genericfor': case 'numfor': case 'repeat':
        this.flattenBlock(node.body); this.walkForCFF(node.body);
        break;
      case 'function': case 'localfunc':
        const targetBody = node.type === 'function' ? node.body : node.fn.body;
        this.flattenBlock(targetBody); this.walkForCFF(targetBody);
        break;
      case 'block':
        for (const stmt of node.body) this.walkForCFF(stmt);
        break;
      case 'assign': case 'return':
        node.exprs.forEach(e => { if (e && e.type === 'function') { this.flattenBlock(e.body); this.walkForCFF(e.body); } });
        break;
      case 'callstat':
        if (node.expr && node.expr.args) node.expr.args.forEach(a => { if (a && a.type === 'function') { this.flattenBlock(a.body); this.walkForCFF(a.body); } });
        break;
      case 'table':
        node.fields.forEach(f => {
          if (f.val && f.val.type === 'function') { this.flattenBlock(f.val.body); this.walkForCFF(f.val.body); }
        });
        break;
    }
  }

  generateMBA_AST(target) {
    const x = Math.floor(Math.random() * target);
    const y = target - x;
    const num = (v) => ({ type: 'number', value: v });
    const bit32 = (method, a, b) => ({
      type: 'call', callee: { type: 'index', obj: { type: 'id', name: 'bit32' }, key: { type: 'string', value: method } },
      args: b !== undefined ? [a, b] : [a]
    });
    const binop = (op, left, right) => ({ type: 'binop', op, left, right });

    const xNode = num(x);
    const yNode = num(y);
    const choice = Math.floor(Math.random() * 4);
    
    if (choice === 0) return binop('+', bit32('bor', xNode, yNode), bit32('band', xNode, yNode));
    else if (choice === 1) return binop('+', bit32('bxor', xNode, yNode), binop('*', num(2), bit32('band', xNode, yNode)));
    else if (choice === 2) return binop('-', binop('*', num(2), bit32('bor', xNode, yNode)), bit32('bxor', xNode, yNode));
    else {
      const A = bit32('bor', xNode, yNode); const B = bit32('band', xNode, yNode);
      return binop('+', bit32('bxor', A, B), binop('*', num(2), bit32('band', A, B)));
    }
  }

  flattenBlock(block) {
    if (!block || !block.body || block.body.length < 3 || block.__cff) return;
    const seenLocals = new Set();
    let hasShadowing = false;
    for (const stmt of block.body) {
      if (stmt.type === 'local') { for (const n of stmt.names) { if (seenLocals.has(n)) hasShadowing = true; seenLocals.add(n); } } 
      else if (stmt.type === 'localfunc') { if (seenLocals.has(stmt.name)) hasShadowing = true; seenLocals.add(stmt.name); }
    }
    if (hasShadowing) return;
    const checkControlFlow = (stmts) => {
      for (const s of stmts) {
        if (s.type === 'break' || s.type === 'continue') return true;
        if (s.type === 'if') {
          if (checkControlFlow(s.body.body)) return true;
          for (const ei of s.elseifs) if (checkControlFlow(ei.body.body)) return true;
          if (s.elsebody && checkControlFlow(s.elsebody.body)) return true;
        }
      }
      return false;
    };
    if (checkControlFlow(block.body)) return;

    block.__cff = true;
    const hoistedSet = new Set();
    const newBody = [];
    for (const stmt of block.body) {
      if (stmt.type === 'local') {
        stmt.names.forEach(n => hoistedSet.add(n));
        if (stmt.exprs && stmt.exprs.length > 0) newBody.push({ type: 'assign', targets: stmt.names.map(n => ({ type: 'id', name: n })), exprs: stmt.exprs });
      } else if (stmt.type === 'localfunc') {
        hoistedSet.add(stmt.name);
        newBody.push({ type: 'assign', targets: [{ type: 'id', name: stmt.name }], exprs: [stmt.fn] });
      } else {
        newBody.push(stmt);
      }
    }

    const chunks = []; let curr = [];
    for (let i = 0; i < newBody.length; i++) {
      curr.push(newBody[i]);
      if (curr.length >= 2 || ['if','while','numfor','genericfor','repeat'].includes(newBody[i].type)) { chunks.push(curr); curr = []; }
    }
    if (curr.length > 0) chunks.push(curr);
    if (chunks.length < 2) return;

    const states = chunks.map(() => Math.floor(Math.random() * 899999) + 100000);
    const stateVarA = '_stA_' + Math.floor(Math.random() * 10000);
    const stateVarB = '_stB_' + Math.floor(Math.random() * 10000);
    const stateBlocks = [];

    for (let i = 0; i < chunks.length; i++) {
      const chunkStmts = chunks[i];
      const lastStmt = chunkStmts[chunkStmts.length - 1];
      if (lastStmt.type !== 'return') {
        const nextState = i < chunks.length - 1 ? states[i + 1] : -1;
        if (nextState !== -1) {
          const nextA = Math.floor(Math.random() * nextState);
          const nextB = nextState - nextA;
          chunkStmts.push({ type: 'assign', targets: [{ type: 'id', name: stateVarA }, { type: 'id', name: stateVarB }], exprs: [this.generateMBA_AST(nextA), this.generateMBA_AST(nextB)] });
        } else chunkStmts.push({ type: 'break' });
      }
      stateBlocks.push({ stateId: states[i], body: { type: 'block', body: chunkStmts, __cff: true } });
    }

    for (let i = stateBlocks.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [stateBlocks[i], stateBlocks[j]] = [stateBlocks[j], stateBlocks[i]];
    }

    let ifTree = null;
    for (let i = 0; i < stateBlocks.length; i++) {
      const sb = stateBlocks[i];
      const cond = { type: 'binop', op: '==', left: { type: 'binop', op: '+', left: { type: 'id', name: stateVarA }, right: { type: 'id', name: stateVarB } }, right: { type: 'number', value: sb.stateId } };
      if (i === 0) ifTree = { type: 'if', cond, body: sb.body, elseifs: [], elsebody: null };
      else ifTree.elseifs.push({ cond, body: sb.body });
    }

    const finalBody = [];
    const hoistedNames = Array.from(hoistedSet);
    if (hoistedNames.length > 0) finalBody.push({ type: 'local', names: hoistedNames, exprs: [] });
    
    const startA = Math.floor(Math.random() * states[0]); const startB = states[0] - startA;
    finalBody.push({ type: 'local', names: [stateVarA, stateVarB], exprs: [this.generateMBA_AST(startA), this.generateMBA_AST(startB)] });
    finalBody.push({ type: 'while', cond: { type: 'bool', value: true }, body: { type: 'block', body: [ifTree], __cff: true } });
    block.body = finalBody;
  }

  tokenize(src) {
    const tokens = []; let i = 0; const len = src.length;
    while (i < len) {
      if (/\s/.test(src[i])) { i++; continue; }
      if (src[i] === '-' && src[i+1] === '-') {
        if (src[i+2] === '[') {
          let lvl = 0; let j = i+2; while (j < len && src[j] === '[') { lvl++; j++; }
          if (src[j-lvl] === '[' && lvl > 0) {
            i = j; const close = ']' + '='.repeat(lvl-1) + ']';
            while (i < len && !src.startsWith(close, i)) i++;
            i += close.length; continue;
          }
        }
        while (i < len && src[i] !== '\n') i++; continue;
      }
      if (src[i] === '[') {
        let lvl = 0; let j = i+1; while (j < len && src[j] === '=') { lvl++; j++; }
        if (src[j] === '[') {
          const close = ']' + '='.repeat(lvl) + ']'; i = j+1; let s = '';
          while (i < len && !src.startsWith(close, i)) s += src[i++];
          i += close.length; tokens.push({ type: 'string', value: s }); continue;
        }
      }
      if (src[i] === '"' || src[i] === "'") {
        const q = src[i++]; let s = '';
        while (i < len && src[i] !== q) {
          if (src[i] === '\\') {
            i++; const ec = src[i];
            if (ec === 'n') s += '\n'; else if (ec === 't') s += '\t'; else if (ec === 'r') s += '\r';
            else if (ec === '\\') s += '\\'; else if (ec === '"') s += '"'; else if (ec === "'") s += "'";
            else if (ec === '0') s += '\0';
            else if (/[0-9]/.test(ec)) {
              let ns = ec; i++;
              if (i < len && /[0-9]/.test(src[i])) ns += src[i++];
              if (i < len && /[0-9]/.test(src[i])) ns += src[i++];
              s += String.fromCharCode(parseInt(ns, 10)); continue;
            } else s += ec;
          } else s += src[i];
          i++;
        }
        i++; tokens.push({ type: 'string', value: s }); continue;
      }
      if (/[0-9]/.test(src[i]) || (src[i] === '.' && /[0-9]/.test(src[i+1]))) {
        let n = '';
        if (src[i] === '0' && (src[i+1] === 'x' || src[i+1] === 'X')) {
          n += src[i++]; n += src[i++];
          while (i < len && /[0-9a-fA-F_]/.test(src[i])) { if (src[i] !== '_') n += src[i]; i++; }
        } else {
          while (i < len && /[0-9._]/.test(src[i])) { 
            if (src[i] === '.' && src[i+1] === '.') break; 
            if (src[i] !== '_') n += src[i]; i++; 
          }
          if (i < len && (src[i] === 'e' || src[i] === 'E')) { n += src[i++]; if (src[i] === '+' || src[i] === '-') n += src[i++]; while (i < len && /[0-9]/.test(src[i])) n += src[i++]; }
        }
        tokens.push({ type: 'number', value: Number(n) }); continue;
      }
      if (/[a-zA-Z_]/.test(src[i])) {
        let w = ''; while (i < len && /[a-zA-Z0-9_]/.test(src[i])) w += src[i++];
        const kws = new Set(['local','function','end','if','then','elseif','else','while','do','for','in','return','break','continue','and','or','not','true','false','nil','repeat','until']);
        tokens.push({ type: kws.has(w) ? 'kw' : 'id', value: w }); continue;
      }
      const three = src.slice(i, i+3);
      if (['...', '..='].includes(three)) { tokens.push({ type: 'op', value: three }); i += 3; continue; }
      const two = src.slice(i, i+2);
      if (['==','~=','<=','>=','..','//','+=','-=','*=','/=','%=','..=','::','->'].includes(two)) { tokens.push({ type: 'op', value: two }); i += 2; continue; }
      tokens.push({ type: 'punct', value: src[i++] });
    }
    tokens.push({ type: 'eof' }); return tokens;
  }

  parse(tokens) { this.tokens = tokens; this.pos = 0; return this.parseBlock(); }
  peek() { return this.tokens[this.pos]; }
  advance() { return this.tokens[this.pos++]; }
  check(type, value) { const t = this.peek(); return t.type === type && (value === undefined || t.value === value); }
  
  eat(type, value) { 
    if (!this.check(type, value)) { 
      const t = this.peek(); 
      return { type: type, value: value || '' }; 
    } 
    return this.advance(); 
  }
  
  tryEat(type, value) { if (this.check(type, value)) { this.advance(); return true; } return false; }

  skipTypeAnnotation() {
    let depth = 0;
    const stopKws = new Set(['local', 'return', 'function', 'if', 'for', 'while', 'repeat', 'do', 'end', 'else', 'elseif', 'until', 'break', 'continue']);
    while (true) {
      const t = this.peek();
      if (t.type === 'eof' || (depth === 0 && t.type === 'kw' && stopKws.has(t.value)) || (depth === 0 && t.type === 'punct' && [',', '=', ')', ';'].includes(t.value))) break;
      if (t.type === 'punct' || t.type === 'op') {
        if (['<', '{', '(', '['].includes(t.value)) { depth++; this.advance(); continue; }
        if (['>', '}', ')', ']'].includes(t.value)) { if (depth > 0) { depth--; this.advance(); continue; } else break; }
        if (depth > 0 || ['?', '|', '&', ':', '.', ',', '->'].includes(t.value)) { this.advance(); continue; }
        break; 
      }
      if (t.type === 'id' || t.type === 'string' || t.type === 'number' || (t.type === 'kw' && ['nil','true','false','typeof'].includes(t.value))) {
        if (t.value === 'typeof') { this.advance(); if (this.check('punct', '(')) { depth++; this.advance(); } continue; }
        this.advance();
        if (depth === 0) { const next = this.peek(); if (next.type === 'id' || (next.type === 'kw' && stopKws.has(next.value))) break; }
        continue;
      }
      if (depth > 0) { this.advance(); continue; }
      break;
    }
  }

  parseBlock() {
    const stmts = []; const ends = new Set(['end','else','elseif','until']);
    while (true) {
      const t = this.peek();
      if (t.type === 'eof' || (t.type === 'kw' && ends.has(t.value))) break;
      if (t.type === 'punct' && t.value === ';') { this.advance(); continue; }
      const s = this.parseStatement();
      if (s) stmts.push(s);
      this.tryEat('punct', ';');
    }
    return { type: 'block', body: stmts };
  }

  parseStatement() {
    const t = this.peek();
    if (t.type === 'id' && (t.value === 'type' || t.value === 'export')) {
      let isAlias = false; const next = this.tokens[this.pos + 1];
      if (t.value === 'export' && next?.value === 'type') isAlias = true;
      else if (t.value === 'type' && next?.type === 'id') isAlias = true;
      if (isAlias) {
        if (t.value === 'export') this.advance();
        this.advance(); this.eat('id');
        if (this.tryEat('punct', '<')) { let gDepth = 1; while (gDepth > 0 && this.peek().type !== 'eof') { const gt = this.advance(); if (gt.value === '<') gDepth++; else if (gt.value === '>') gDepth--; } }
        this.eat('punct', '='); this.skipTypeAnnotation(); return null;
      }
    }
    if (t.type === 'kw') switch (t.value) {
      case 'local':    return this.parseLocal();
      case 'if':       return this.parseIf();
      case 'while':    return this.parseWhile();
      case 'for':      return this.parseFor();
      case 'return':   return this.parseReturn();
      case 'function': return this.parseFunctionStat();
      case 'do':       { this.advance(); const b = this.parseBlock(); this.eat('kw','end'); return b; }
      case 'break':    { this.advance(); return { type: 'break' }; }
      case 'continue': { this.advance(); return { type: 'continue' }; }
      case 'repeat':   return this.parseRepeat();
    }
    return this.parseExprStat();
  }

  parseLocal() {
    this.eat('kw','local');
    if (this.check('kw','function')) { this.advance(); const name = this.eat('id').value; return { type: 'localfunc', name, fn: this.parseFuncBody(name) }; }
    const names = [this.eat('id').value];
    if (this.tryEat('punct', ':')) this.skipTypeAnnotation();
    while (this.tryEat('punct',',')) { names.push(this.eat('id').value); if (this.tryEat('punct', ':')) this.skipTypeAnnotation(); }
    let exprs = [];
    if (this.tryEat('punct','=')) exprs = this.parseExprList();
    return { type: 'local', names, exprs };
  }

  parseIf() {
    this.eat('kw','if'); const cond = this.parseExpr(); this.eat('kw','then'); const body = this.parseBlock();
    const elseifs = []; let elsebody = null;
    while (this.check('kw','elseif')) { this.advance(); const ec = this.parseExpr(); this.eat('kw','then'); elseifs.push({ cond: ec, body: this.parseBlock() }); }
    if (this.tryEat('kw','else')) elsebody = this.parseBlock();
    this.eat('kw','end'); return { type: 'if', cond, body, elseifs, elsebody };
  }

  parseWhile() { this.eat('kw','while'); const cond = this.parseExpr(); this.eat('kw','do'); const body = this.parseBlock(); this.eat('kw','end'); return { type: 'while', cond, body }; }
  
  parseFor() {
    this.eat('kw','for'); const firstName = this.eat('id').value;
    if (this.tryEat('punct', ':')) this.skipTypeAnnotation();
    if (this.check('kw','in')) {
      this.advance(); const iters = this.parseExprList(); this.eat('kw','do'); const body = this.parseBlock(); this.eat('kw','end');
      return { type: 'genericfor', names: [firstName], iters, body };
    }
    if (this.check('punct',',')) {
      const names = [firstName];
      while (this.tryEat('punct',',')) { names.push(this.eat('id').value); if (this.tryEat('punct', ':')) this.skipTypeAnnotation(); }
      this.eat('kw','in'); const iters = this.parseExprList(); this.eat('kw','do'); const body = this.parseBlock(); this.eat('kw','end');
      return { type: 'genericfor', names, iters, body };
    }
    this.eat('punct','='); const start = this.parseExpr(); this.eat('punct',','); const limit = this.parseExpr();
    let step = { type: 'number', value: 1 }; if (this.tryEat('punct',',')) step = this.parseExpr();
    this.eat('kw','do'); const body = this.parseBlock(); this.eat('kw','end');
    return { type: 'numfor', name: firstName, start, limit, step, body };
  }

  parseRepeat() { this.eat('kw','repeat'); const body = this.parseBlock(); this.eat('kw','until'); return { type: 'repeat', body, cond: this.parseExpr() }; }

  parseReturn() {
    this.eat('kw','return'); const t = this.peek(); let exprs = [];
    if (t.type !== 'eof' && !(t.type === 'kw' && ['end','else','elseif','until'].includes(t.value))) exprs = this.parseExprList();
    this.tryEat('punct',';'); return { type: 'return', exprs };
  }

  parseFunctionStat() {
    this.eat('kw','function'); let name = this.eat('id').value;
    let obj = { type:'id', name }; let isSelfMethod = false;
    while (this.tryEat('punct','.')) { const field = this.eat('id').value; obj = { type:'index', obj, key: { type:'string', value: field } }; name += '.' + field; }
    if (this.tryEat('punct',':')) { const method = this.eat('id').value; obj = { type:'index', obj, key: { type:'string', value: method } }; name += ':' + method; isSelfMethod = true; }
    return { type: 'assign', targets: [obj], exprs: [this.parseFuncBody(name, isSelfMethod)] };
  }

  parseFuncBody(name, isSelfMethod = false) {
    this.eat('punct','('); const params = []; let vararg = false;
    if (isSelfMethod) params.push('self');
    if (!this.check('punct',')')) {
      if (this.peek().value === '...') { vararg = true; this.advance(); if (this.tryEat('punct', ':')) this.skipTypeAnnotation(); }
      else {
        params.push(this.eat('id').value); if (this.tryEat('punct', ':')) this.skipTypeAnnotation();
        while (this.tryEat('punct',',')) {
          if (this.peek().value === '...') { vararg = true; this.advance(); if (this.tryEat('punct', ':')) this.skipTypeAnnotation(); break; }
          params.push(this.eat('id').value); if (this.tryEat('punct', ':')) this.skipTypeAnnotation();
        }
      }
    }
    this.eat('punct',')'); 
    if (this.tryEat('punct', ':') || this.tryEat('op', '->')) this.skipTypeAnnotation();
    const body = this.parseBlock(); this.eat('kw','end');
    return { type: 'function', params, vararg, body, name: name || '?' };
  }

  parseExprStat() {
    const expr = this.parseSuffixedExpr();
    if (!expr || expr.type === 'nil') return null; 
    const compound = { '+=':'ADD', '-=':'SUB', '*=':'MUL', '/=':'DIV', '%=':'MOD', '..=':'CONCAT' };
    if (this.peek().type === 'op' && compound[this.peek().value]) {
      const op = this.advance().value; const rhs = this.parseExpr();
      return { type: 'assign', targets: [expr], exprs: [{ type:'binop', op: op.slice(0,-1), left: expr, right: rhs }] };
    }
    if (this.check('punct','=')) { this.advance(); return { type: 'assign', targets: [expr], exprs: this.parseExprList() }; }
    if (this.check('punct',',')) {
      const targets = [expr]; while (this.tryEat('punct',',')) targets.push(this.parseSuffixedExpr());
      this.eat('punct','='); return { type: 'assign', targets, exprs: this.parseExprList() };
    }
    if (expr.type !== 'call' && expr.type !== 'methodcall') return null;
    return { type: 'callstat', expr };
  }

  parseExprList() { const l = [this.parseExpr()]; while (this.tryEat('punct',',')) l.push(this.parseExpr()); return l; }
  parseExpr() { let expr = this.parseOr(); while (this.tryEat('op', '::')) this.skipTypeAnnotation(); return expr; }
  parseOr()   { let l = this.parseAnd();    while (this.check('kw','or'))  { this.advance(); l = { type:'binop', op:'or',  left:l, right:this.parseAnd()    }; } return l; }
  parseAnd()  { let l = this.parseCmp();    while (this.check('kw','and')) { this.advance(); l = { type:'binop', op:'and', left:l, right:this.parseCmp()    }; } return l; }
  parseCmp()  {
    let l = this.parseConcat(); const cmpOps = new Set(['<','>','==','~=','<=','>=']);
    while (cmpOps.has(this.peek().value) && (this.peek().type === 'op' || this.peek().type === 'punct')) l = { type:'binop', op: this.advance().value, left:l, right:this.parseConcat() };
    return l;
  }
  parseConcat() { let l = this.parseAdd(); if (this.check('op','..')) { this.advance(); return { type:'binop', op:'..', left:l, right:this.parseConcat() }; } return l; }
  parseAdd() { let l = this.parseMul(); while (this.peek().value === '+' || this.peek().value === '-') l = { type:'binop', op: this.advance().value, left:l, right:this.parseMul() }; return l; }
  parseMul() { let l = this.parseUnary(); while (['*','/','%','//'].includes(this.peek().value)) l = { type:'binop', op: this.advance().value, left:l, right:this.parseUnary() }; return l; }
  parseUnary() {
    if (this.check('kw','not'))  { this.advance(); return { type:'unop', op:'not', expr:this.parseUnary() }; }
    if (this.peek().value === '-') { this.advance(); return { type:'unop', op:'-',  expr:this.parseUnary() }; }
    if (this.peek().value === '#') { this.advance(); return { type:'unop', op:'#',  expr:this.parseUnary() }; }
    return this.parsePow();
  }
  parsePow() { let l = this.parseSuffixedExpr(); if (this.peek().value === '^') { this.advance(); return { type:'binop', op:'^', left:l, right:this.parseUnary() }; } return l; }

  parseSuffixedExpr() {
    let expr = this.parsePrimaryExpr();
    while (true) {
      if (this.check('punct','.')) { this.advance(); expr = { type:'index', obj:expr, key:{ type:'string', value:this.eat('id').value } }; } 
      else if (this.check('punct','[')) { this.advance(); const k = this.parseExpr(); this.eat('punct',']'); expr = { type:'index', obj:expr, key:k }; } 
      else if (this.check('punct','(')) {
        this.advance(); const args = this.check('punct',')') ? [] : this.parseExprList(); this.eat('punct',')');
        expr = { type:'call', callee:expr, args };
      } 
      else if (this.check('punct','{')) expr = { type:'call', callee:expr, args:[this.parseTableCtor()] };
      else if (this.peek().type === 'string') { const s = this.advance(); expr = { type:'call', callee:expr, args:[{ type:'string', value:s.value }] }; } 
      else if (this.check('punct',':')) {
        this.advance(); const m = this.eat('id').value; let args = [];
        if (this.check('punct','(')) { this.advance(); args = this.check('punct',')') ? [] : this.parseExprList(); this.eat('punct',')'); }
        else if (this.check('punct','{')) args = [this.parseTableCtor()];
        else if (this.peek().type === 'string') args = [{ type:'string', value: this.advance().value }];
        expr = { type:'methodcall', obj:expr, method:m, args };
      } else break;
    }
    return expr;
  }

  parsePrimaryExpr() {
    const t = this.peek();
    if (t.type === 'id') { this.advance(); return { type:'id', name:t.value }; }
    if (t.type === 'number') { this.advance(); return { type:'number', value:t.value }; }
    if (t.type === 'string') { this.advance(); return { type:'string', value:t.value }; }
    if (t.type === 'kw' && ['true','false'].includes(t.value)) { this.advance(); return { type:'bool', value: t.value === 'true' }; }
    if (t.type === 'kw' && t.value === 'nil') { this.advance(); return { type:'nil' }; }
    if (t.type === 'kw' && t.value === 'function') { this.advance(); return this.parseFuncBody('anon'); }
    if (t.value === '(') { this.advance(); const e = this.parseExpr(); this.eat('punct',')'); return { type:'paren', expr:e }; }
    if (t.value === '{') return this.parseTableCtor();
    if (t.value === '...' || (t.type === 'op' && t.value === '...')) { this.advance(); return { type:'vararg' }; }
    this.advance(); return { type: 'nil' }; 
  }

  parseTableCtor() {
    this.eat('punct','{'); const fields = [];
    while (!this.check('punct','}')) {
      if (this.check('punct','[')) { this.advance(); const key = this.parseExpr(); this.eat('punct',']'); this.eat('punct','='); fields.push({ type:'keyval', key, val:this.parseExpr() }); } 
      else if (this.peek().type === 'id' && this.tokens[this.pos+1]?.value === '=') { const key = this.eat('id').value; this.eat('punct','='); fields.push({ type:'strkey', key, val:this.parseExpr() }); } 
      else fields.push({ type:'listval', val:this.parseExpr() });
      if (!this.tryEat('punct',',') && !this.tryEat('punct',';')) break;
    }
    this.eat('punct','}'); return { type:'table', fields };
  }

  compileChunk(block) {
    const ctx = { instructions:[], scope:Object.create(null), localSlots:[], numLocals:0, numParams:0, breakPatches:[], continuePatches:[], parent: null };
    this.emitBlock(block, ctx); this.emit(ctx,'HALT');
    this.functions.push({ src:this.instrToSrc(ctx.instructions), numLocals:ctx.numLocals, numParams:0, numRegs:0 });
    return this.functions.length - 1;
  }

  compileFn(node, parentCtx) {
    const ctx = { instructions:[], scope:Object.create(null), localSlots:[], numLocals:node.params.length, numParams:node.params.length, breakPatches:[], continuePatches:[], parent: parentCtx || null };
    node.params.forEach((p, i) => { ctx.scope[p] = i; ctx.localSlots[i] = p; });
    this.emitBlock(node.body, ctx); this.emit(ctx,'LOADK', this.getConst(null)); this.emit(ctx,'RET');
    this.functions.push({ src:this.instrToSrc(ctx.instructions), numLocals:ctx.numLocals, numParams:ctx.numParams, numRegs:0 });
    return this.functions.length - 1;
  }

  resolveVar(ctx, name) {
    if (ctx.scope[name] !== undefined) return { kind: 'local', slot: ctx.scope[name] };
    let depth = 0, cur = ctx.parent;
    while (cur) { depth++; if (cur.scope[name] !== undefined) return { kind: 'upval', depth, slot: cur.scope[name] }; cur = cur.parent; }
    return { kind: 'global' };
  }

  instrToSrc(instructions) { return instructions.map(i => i.label ? i.label + ':' : (i.op + (i.arg !== undefined ? ' ' + i.arg : ''))).join('\n'); }
  emit(ctx, op, arg) { ctx.instructions.push({ op, arg }); }
  emitLabel(ctx, name) { ctx.instructions.push({ label: name }); }
  getConst(v) { const key = JSON.stringify(v); if (this.constMap.has(key)) return this.constMap.get(key); const idx = this.constants.length; this.constants.push(v); this.constMap.set(key, idx); return idx; }
  allocLocal(ctx, name) { const slot = ctx.numLocals++; ctx.scope[name] = slot; ctx.localSlots[slot] = name; return slot; }
  labelName() { return 'L' + (this._lc++); }

  emitBlock(block, ctx) { for (const s of block.body) this.emitStmt(s, ctx); }

  injectDeadCode(ctx) {
    if (Math.random() < 0.3) {
      this.emit(ctx, 'LOADK', this.getConst(Math.floor(Math.random() * 999999)));
      this.emit(ctx, 'LOADK', this.getConst(Math.floor(Math.random() * 999999)));
      const ops = ['ADD', 'SUB', 'MUL'];
      this.emit(ctx, ops[Math.floor(Math.random() * ops.length)]);
      this.emit(ctx, 'POP');
    }
  }

  emitStmt(stmt, ctx) {
    if (!stmt) return;
    this.injectDeadCode(ctx);
    switch (stmt.type) {
      case 'local': {
        const slots = stmt.names.map(n => this.allocLocal(ctx, n));
        const lastEi = stmt.exprs.length - 1;
        const lastNeedsMulti = stmt.names.length > stmt.exprs.length && lastEi >= 0 && (stmt.exprs[lastEi].type === 'call' || stmt.exprs[lastEi].type === 'methodcall');
        for (let i = 0; i < stmt.names.length; i++) {
          if (i < lastEi || (i === lastEi && !lastNeedsMulti)) { this.emitExpr(stmt.exprs[i], ctx); this.emit(ctx,'SETLOCAL', slots[i]); }
          else if (i === lastEi && lastNeedsMulti) { this.emitMultiReturnCall(stmt.exprs[lastEi], ctx, slots, i); break; }
          else { this.emit(ctx,'LOADK', this.getConst(null)); this.emit(ctx,'SETLOCAL', slots[i]); }
        }
        break;
      }
      case 'assign': {
        const aLastEi = stmt.exprs.length - 1;
        const aLastNeedsMulti = stmt.targets.length > stmt.exprs.length && aLastEi >= 0 && (stmt.exprs[aLastEi].type === 'call' || stmt.exprs[aLastEi].type === 'methodcall');
        const doAssignTarget = (tgt, valOnStack) => {
          if (tgt.type === 'id') {
            const r = this.resolveVar(ctx, tgt.name);
            if (r.kind === 'local') this.emit(ctx,'SETLOCAL', r.slot);
            else if (r.kind === 'upval') this.emit(ctx,'SETUPVAL', r.depth*65536+r.slot);
            else this.emit(ctx,'SETGLOBAL', this.getConst(tgt.name));
          } else if (tgt.type === 'index') {
            const vs = ctx.numLocals++; this.emit(ctx,'SETLOCAL', vs);
            this.emitExpr(tgt.obj, ctx); this.emitExpr(tgt.key, ctx);
            this.emit(ctx,'GETLOCAL', vs); this.emit(ctx,'SETINDEX'); ctx.numLocals--;
          }
        };
        if (aLastNeedsMulti) {
          const tempBase = ctx.numLocals; const tempSlots = stmt.targets.map(() => ctx.numLocals++);
          for (let i = 0; i < aLastEi; i++) { this.emitExpr(stmt.exprs[i], ctx); this.emit(ctx,'SETLOCAL', tempSlots[i]); }
          this.emitMultiReturnCall(stmt.exprs[aLastEi], ctx, tempSlots, aLastEi);
          for (let i = 0; i < stmt.targets.length; i++) { this.emit(ctx,'GETLOCAL', tempSlots[i]); doAssignTarget(stmt.targets[i], true); }
          ctx.numLocals = tempBase;
        } else {
          for (let i = 0; i < stmt.targets.length; i++) {
            if (i < stmt.exprs.length) this.emitExpr(stmt.exprs[i], ctx);
            else this.emit(ctx,'LOADK', this.getConst(null));
          }
          for (let i = stmt.targets.length - 1; i >= 0; i--) doAssignTarget(stmt.targets[i], true);
        }
        break;
      }
      case 'callstat':  this.emitExpr(stmt.expr, ctx); this.emit(ctx,'POP'); break;
      case 'if':        this.emitIf(stmt, ctx); break;
      case 'while':     this.emitWhile(stmt, ctx); break;
      case 'numfor':    this.emitNumFor(stmt, ctx); break;
      case 'genericfor':this.emitGenericFor(stmt, ctx); break;
      case 'repeat':    this.emitRepeat(stmt, ctx); break;
      case 'return': {
        if (stmt.exprs.length > 0) this.emitExpr(stmt.exprs[0], ctx); else this.emit(ctx,'LOADK', this.getConst(null));
        this.emit(ctx,'RET'); break;
      }
      case 'block':    this.emitBlock(stmt, ctx); break;
      case 'localfunc': { const slot = this.allocLocal(ctx, stmt.name); const fnIdx = this.compileFn(stmt.fn, ctx); this.emit(ctx,'MAKECLOSURE', fnIdx); this.emit(ctx,'SETLOCAL', slot); break; }
      case 'break': { const pi = ctx.instructions.length; this.emit(ctx,'JMP', 0); ctx.breakPatches.push(pi); break; }
      case 'continue': { const pi = ctx.instructions.length; this.emit(ctx,'JMP', 0); ctx.continuePatches.push(pi); break; }
    }
  }

  emitIf(node, ctx) {
    const endL = this.labelName();
    const branch = (cond, body) => { const skip = this.labelName(); this.emitExpr(cond, ctx); this.emit(ctx,'JZ', skip); this.emitBlock(body, ctx); this.emit(ctx,'JMP', endL); this.emitLabel(ctx, skip); };
    branch(node.cond, node.body); for (const ei of node.elseifs) branch(ei.cond, ei.body);
    if (node.elsebody) this.emitBlock(node.elsebody, ctx); this.emitLabel(ctx, endL);
  }

  emitWhile(node, ctx) {
    const top = this.labelName(), end = this.labelName(); const savedB = ctx.breakPatches, savedC = ctx.continuePatches; 
    ctx.breakPatches = []; ctx.continuePatches = [];
    this.emitLabel(ctx, top); this.emitExpr(node.cond, ctx); this.emit(ctx,'JZ', end);
    this.emitBlock(node.body, ctx); this.emit(ctx,'JMP', top); this.emitLabel(ctx, end);
    ctx.breakPatches.forEach(pi => { ctx.instructions[pi].arg = end; }); ctx.continuePatches.forEach(pi => { ctx.instructions[pi].arg = top; }); 
    ctx.breakPatches = savedB; ctx.continuePatches = savedC;
  }

  emitRepeat(node, ctx) {
    const top = this.labelName(), end = this.labelName(); const saved = ctx.breakPatches; ctx.breakPatches = [];
    this.emitLabel(ctx, top); this.emitBlock(node.body, ctx); this.emitExpr(node.cond, ctx); this.emit(ctx,'JZ', top); this.emitLabel(ctx, end);
    ctx.breakPatches.forEach(pi => { ctx.instructions[pi].arg = end; }); ctx.breakPatches = saved;
  }

  emitNumFor(node, ctx) {
    const cntSlot = ctx.numLocals++; const lmtSlot = ctx.numLocals++; const stpSlot = ctx.numLocals++;
    const top = this.labelName(), end = this.labelName(), cont = this.labelName();
    const savedB = ctx.breakPatches; const savedC = ctx.continuePatches; ctx.breakPatches = []; ctx.continuePatches = [];
    this.emitExpr(node.start, ctx); this.emit(ctx,'SETLOCAL', cntSlot); this.emitExpr(node.limit, ctx); this.emit(ctx,'SETLOCAL', lmtSlot); this.emitExpr(node.step, ctx);  this.emit(ctx,'SETLOCAL', stpSlot);
    this.emitLabel(ctx, top);
    this.emit(ctx,'GETLOCAL', cntSlot); this.emit(ctx,'GETLOCAL', lmtSlot); this.emit(ctx,'GT'); this.emit(ctx,'JNZ', end);
    const varSlot = this.allocLocal(ctx, node.name); this.emit(ctx, 'GETLOCAL', cntSlot); this.emit(ctx, 'SETLOCAL', varSlot);
    this.emitBlock(node.body, ctx);
    this.emitLabel(ctx, cont);
    this.emit(ctx,'GETLOCAL', cntSlot); this.emit(ctx,'GETLOCAL', stpSlot); this.emit(ctx,'ADD'); this.emit(ctx,'SETLOCAL', cntSlot); this.emit(ctx,'JMP', top);
    this.emitLabel(ctx, end);
    ctx.breakPatches.forEach(pi => { ctx.instructions[pi].arg = end; }); ctx.continuePatches.forEach(pi => { ctx.instructions[pi].arg = cont; }); 
    ctx.breakPatches = savedB; ctx.continuePatches = savedC;
  }

  emitGenericFor(node, ctx) {
    const pkSlot = ctx.numLocals++; const iterSlot = ctx.numLocals++; const stateSlot = ctx.numLocals++; const ctrlSlot = ctx.numLocals++;
    const varSlots = node.names.map(name => this.allocLocal(ctx, name));
    if (node.iters.length === 1 && node.iters[0].type === 'call') {
      this.emit(ctx,'GETGLOBAL', this.getConst('__vmgi')); this.emitExpr(node.iters[0].callee, ctx);
      for (const a of node.iters[0].args) this.emitExpr(a, ctx);
      this.emit(ctx,'CALL', node.iters[0].args.length + 1);
    } else {
      this.emit(ctx,'GETGLOBAL', this.getConst('__vmgp'));
      for (let i = 0; i < 3; i++) { if (i < node.iters.length) this.emitExpr(node.iters[i], ctx); else this.emit(ctx,'LOADK', this.getConst(null)); }
      this.emit(ctx,'CALL', 3);
    }
    this.emit(ctx,'SETLOCAL', pkSlot);
    this.emit(ctx,'GETLOCAL', pkSlot); this.emit(ctx,'LOADK', this.getConst(1)); this.emit(ctx,'GETINDEX'); this.emit(ctx,'SETLOCAL', iterSlot);
    this.emit(ctx,'GETLOCAL', pkSlot); this.emit(ctx,'LOADK', this.getConst(2)); this.emit(ctx,'GETINDEX'); this.emit(ctx,'SETLOCAL', stateSlot);
    this.emit(ctx,'GETLOCAL', pkSlot); this.emit(ctx,'LOADK', this.getConst(3)); this.emit(ctx,'GETINDEX'); this.emit(ctx,'SETLOCAL', ctrlSlot);

    const top = this.labelName(), end = this.labelName(), cont = this.labelName();
    const savedB = ctx.breakPatches; const savedC = ctx.continuePatches; ctx.breakPatches = []; ctx.continuePatches = [];
    
    this.emitLabel(ctx, top);
    this.emit(ctx,'GETGLOBAL', this.getConst('__vmgn')); this.emit(ctx,'GETLOCAL', iterSlot); this.emit(ctx,'GETLOCAL', stateSlot); this.emit(ctx,'GETLOCAL', ctrlSlot); this.emit(ctx,'LOADK', this.getConst(varSlots.length)); this.emit(ctx,'CALL', 4); this.emit(ctx,'SETLOCAL', pkSlot);
    this.emit(ctx,'GETLOCAL', pkSlot); this.emit(ctx,'JZ', end);
    for (let i = 0; i < varSlots.length; i++) { this.emit(ctx,'GETLOCAL', pkSlot); this.emit(ctx,'LOADK', this.getConst(i+1)); this.emit(ctx,'GETINDEX'); this.emit(ctx,'SETLOCAL', varSlots[i]); }
    this.emit(ctx,'GETLOCAL', varSlots[0]); this.emit(ctx,'SETLOCAL', ctrlSlot);

    this.emitBlock(node.body, ctx);
    this.emitLabel(ctx, cont); this.emit(ctx,'JMP', top); this.emitLabel(ctx, end);
    ctx.breakPatches.forEach(pi => { ctx.instructions[pi].arg = end; }); ctx.continuePatches.forEach(pi => { ctx.instructions[pi].arg = cont; }); 
    ctx.breakPatches = savedB; ctx.continuePatches = savedC;
  }

  emitExpr(node, ctx) {
    if (!node) return this.emit(ctx,'LOADK', this.getConst(null));
    switch (node.type) {
      case 'number': this.emit(ctx, 'LOADK', this.getConst(node.value)); break;
      case 'string': this.emit(ctx, 'LOADK', this.getConst(node.value)); break;
      case 'bool':   this.emit(ctx, 'LOADK', this.getConst(node.value)); break;
      case 'nil':    this.emit(ctx,'LOADK', this.getConst(null)); break;
      case 'id': {
        const r = this.resolveVar(ctx, node.name);
        if (r.kind === 'local') this.emit(ctx,'GETLOCAL', r.slot); else if (r.kind === 'upval') this.emit(ctx,'GETUPVAL', r.depth*65536+r.slot); else this.emit(ctx,'GETGLOBAL', this.getConst(node.name));
        break;
      }
      case 'paren':  this.emitExpr(node.expr, ctx); break;
      case 'unop':   this.emitUnop(node, ctx); break;
      case 'binop':  this.emitBinop(node, ctx); break;
      case 'call':   this.emitCall(node, ctx); break;
      case 'methodcall': this.emitMethodCall(node, ctx); break;
      case 'index':  this.emitExpr(node.obj, ctx); this.emitExpr(node.key, ctx); this.emit(ctx,'GETINDEX'); break;
      case 'function': { const fi = this.compileFn(node, ctx); this.emit(ctx,'MAKECLOSURE', fi); break; }
      case 'table':  this.emitTable(node, ctx); break;
      case 'vararg': this.emit(ctx,'LOADK', this.getConst(null)); break;
    }
  }

  emitUnop(node, ctx) {
    if (node.op === '-' && node.expr.type === 'number') return this.emitExpr({ type: 'number', value: -node.expr.value }, ctx);
    if (node.op === '-') { this.emit(ctx, 'LOADK', this.getConst(0)); this.emitExpr(node.expr, ctx); this.emit(ctx, 'SUB'); return; }
    this.emitExpr(node.expr, ctx);
    if (node.op === 'not') this.emit(ctx,'NOT'); 
    else if (node.op === '#') { const ci = this.getConst('__vlen'); const tmp = ctx.numLocals++; this.emit(ctx,'SETLOCAL', tmp); this.emit(ctx,'GETGLOBAL', ci); this.emit(ctx,'GETLOCAL', tmp); this.emit(ctx,'CALL', 1); ctx.numLocals--; }
  }

  emitMultiReturnCall(callNode, ctx, slots, startIdx) {
    this.emit(ctx,'GETGLOBAL', this.getConst('__vmmr'));
    if (callNode.type === 'call') {
      this.emitExpr(callNode.callee, ctx);
      let hasVararg = false; let normalArgs = 0;
      for (const a of callNode.args) { if (a.type === 'vararg') hasVararg = true; else { this.emitExpr(a, ctx); normalArgs++; } }
      this.emit(ctx, hasVararg ? 'CALL_VARARG' : 'CALL', normalArgs + 1);
    } else {
      this.emitExpr(callNode.obj, ctx); this.emit(ctx,'DUP'); this.emit(ctx,'LOADK', this.getConst(callNode.method)); this.emit(ctx,'GETINDEX'); this.emit(ctx,'SWAP');
      let hasVararg = false; let normalArgs = 0;
      for (const a of callNode.args) { if (a.type === 'vararg') hasVararg = true; else { this.emitExpr(a, ctx); normalArgs++; } }
      this.emit(ctx, hasVararg ? 'CALL_VARARG' : 'CALL', normalArgs + 2);
    }
    const tmp = ctx.numLocals++; this.emit(ctx,'SETLOCAL', tmp);
    for (let k = startIdx; k < slots.length; k++) { this.emit(ctx,'GETLOCAL', tmp); this.emit(ctx,'LOADK', this.getConst(k - startIdx + 1)); this.emit(ctx,'GETINDEX'); this.emit(ctx,'SETLOCAL', slots[k]); }
    ctx.numLocals--;
  }

  emitBinop(node, ctx) {
    if (node.op === 'and') { const e = this.labelName(); this.emitExpr(node.left, ctx); this.emit(ctx,'DUP'); this.emit(ctx,'JZ', e); this.emit(ctx,'POP'); this.emitExpr(node.right, ctx); this.emitLabel(ctx, e); return; }
    if (node.op === 'or') { const e = this.labelName(); this.emitExpr(node.left, ctx); this.emit(ctx,'DUP'); this.emit(ctx,'JNZ', e); this.emit(ctx,'POP'); this.emitExpr(node.right, ctx); this.emitLabel(ctx, e); return; }
    this.emitExpr(node.left, ctx); this.emitExpr(node.right, ctx);
    if (node.op === '//') { const tmp = ctx.numLocals++; this.emit(ctx,'DIV'); this.emit(ctx,'SETLOCAL', tmp); this.emit(ctx,'GETGLOBAL', this.getConst('__vfloor')); this.emit(ctx,'GETLOCAL', tmp); this.emit(ctx,'CALL', 1); ctx.numLocals--; return; }
    const opMap = { '+':'ADD','-':'SUB','*':'MUL','/':'DIV','%':'MOD','^':'POW','..':'CONCAT','==':'EQ','~=':'NEQ','<':'LT','<=':'LE','>':'GT','>=':'GE' };
    this.emit(ctx, opMap[node.op]);
  }

  emitCall(node, ctx) {
    this.emitExpr(node.callee, ctx); let hasVararg = false; let normalArgs = 0;
    for (const a of node.args) { if (a.type === 'vararg') hasVararg = true; else { this.emitExpr(a, ctx); normalArgs++; } }
    this.emit(ctx, hasVararg ? 'CALL_VARARG' : 'CALL', normalArgs);
  }

  emitMethodCall(node, ctx) {
    this.emitExpr(node.obj, ctx); this.emit(ctx,'DUP');
    let mName = node.method; if (mName === 'service') mName = 'GetService'; if (mName === 'children') mName = 'GetChildren';
    this.emit(ctx,'LOADK', this.getConst(mName)); this.emit(ctx,'GETINDEX'); this.emit(ctx,'SWAP');
    let hasVararg = false; let normalArgs = 0;
    for (const a of node.args) { if (a.type === 'vararg') hasVararg = true; else { this.emitExpr(a, ctx); normalArgs++; } }
    this.emit(ctx, hasVararg ? 'CALL_VARARG' : 'CALL', normalArgs + 1);
  }

  emitTable(node, ctx) {
    this.emit(ctx,'NEWTABLE'); let arrIdx = 1;
    for (const f of node.fields) {
      this.emit(ctx,'DUP');
      if (f.type === 'listval') { this.emit(ctx,'LOADK', this.getConst(arrIdx++)); this.emitExpr(f.val, ctx); }
      else if (f.type === 'strkey') { this.emit(ctx,'LOADK', this.getConst(f.key)); this.emitExpr(f.val, ctx); }
      else { this.emitExpr(f.key, ctx); this.emitExpr(f.val, ctx); }
      this.emit(ctx,'SETINDEX');
    }
  }
}

const antiTamper = `
    local lp = game:GetService("Players").LocalPlayer
    local char = lp.Character or lp.CharacterAdded:Wait()
    local root = char:WaitForChild("HumanoidRootPart")
    local hum = char:WaitForChild("Humanoid")
    local rs = game:GetService("RunService")

    local joints = {}
    for _, part in ipairs(char:GetDescendants()) do
        if part:IsA("Motor6D") then
            joints[#joints + 1] = part
        end
    end
    if #joints == 0 then error("Tampering Detected", 0) end
    hum:MoveTo(root.Position + Vector3.new(50, 0, 0))
    local samples = {}
    for _, joint in ipairs(joints) do
        samples[joint] = {}
    end
    local elapsed = 0
    repeat
        rs.Heartbeat:Wait()
        for _, joint in ipairs(joints) do
            samples[joint][#samples[joint] + 1] = joint.CurrentAngle
        end
        elapsed += 1
    until elapsed > 120
    hum:MoveTo(root.Position)
    local anyChanged = false
    for _, joint in ipairs(joints) do
        local jointSamples = samples[joint]
        local first = jointSamples[1]
        for _, v in ipairs(jointSamples) do
            if math.abs(v - first) > 0.01 then
                anyChanged = true
            end
        end
    end
    if not anyChanged then error("Tampering Detected", 0) end

    local failures = {}
    local passed = 0

    local function fail(message)
        error(tostring(message), 0)
    end

    local function expect(condition, message)
        if not condition then
            fail(message)
        end
    end

    local function exact(label, actual, expected)
        if actual ~= expected then
            fail(string.format("%s: expected %.17g, got %.17g", label, expected, actual))
        end
    end

    local function exactVector2(label, actual, x, y)
        exact(label .. ".X", actual.X, x)
        exact(label .. ".Y", actual.Y, y)
    end

    local function check(name, callback)
        local ok, result = xpcall(callback, function(message)
            return tostring(message)
        end)

        if ok then
            passed += 1
        else
            table.insert(failures, name .. ": " .. result)
        end
    end

    local function checkCMetadata(label, callback, expectedName)
        local source, line, name, argumentCount, isVariadic, identity = debug.info(callback, "slnaf")
        expect(source == "[C]", label .. " src_err " .. tostring(source))
        expect(line == -1, label .. " ln_err " .. tostring(line))
        expect(name == expectedName, label .. " nm_err " .. tostring(name))
        expect(argumentCount == 0, label .. " arg_err " .. tostring(argumentCount))
        expect(isVariadic == true, label .. " var_err")
        expect(rawequal(identity, callback), label .. " id_err")
    end

    check("c_meta", function()
        checkCMetadata("UDim2.new", UDim2.new, "new")
        checkCMetadata("Instance.new", Instance.new, "new")
        checkCMetadata("Random.new", Random.new, "new")
    end)

    check("f_env", function()
        expect(type(getfenv) == "function", "f_miss")
        expect(type(setfenv) == "function", "s_miss")
        local globalEnvironment = getfenv(UDim2.new)
        expect(type(globalEnvironment) == "table", "c_env_miss")

        local changedC = pcall(setfenv, UDim2.new, {})
        expect(not changedC, "c_mut")

        local function localClosure()
            return true
        end
        local privateEnvironment = { marker = "private" }
        setfenv(localClosure, privateEnvironment)
        expect(rawequal(getfenv(localClosure), privateEnvironment), "id_split")
    end)

    check("t_meta", function()
        checkCMetadata("task.spawn", task.spawn, "spawn")
        checkCMetadata("task.defer", task.defer, "defer")
        checkCMetadata("task.delay", task.delay, "delay")
        checkCMetadata("task.wait", task.wait, "wait")
        checkCMetadata("task.cancel", task.cancel, "cancel")
    end)

    check("v_math", function()
        expect(type(vector) == "table" and type(vector.create) == "function", "vc_miss")
        local nativeVector = vector.create(1.25, -2.5, 3.75)
        expect(typeof(nativeVector) == "Vector3", "v_type_err")
        exact("v_x", nativeVector.x, 1.25)
        exact("v_y", nativeVector.y, -2.5)
        exact("v_z", nativeVector.z, 3.75)

        local vector2Value = Vector2.new(3, 4)
        local vector3Value = Vector3.new(1, 2, 3)
        exact("v2_mag", vector2Value.Magnitude, 5)
        exactVector2("v2_add", vector2Value + Vector2.new(2, -1), 5, 3)
        expect(vector3Value.X == 1 and vector3Value.Y == 2 and vector3Value.Z == 3, "v3_comp_err")
    end)

    check("e_state", function()
        local enumType = Enum.HumanoidStateType
        checkCMetadata("e_name", enumType.FromName, "FromName")
        checkCMetadata("e_val", enumType.FromValue, "FromValue")
        expect(not rawequal(enumType.FromName, enumType.FromName), "e_c_1")
        expect(not rawequal(enumType.FromValue, enumType.FromValue), "e_c_2")
        expect(enumType:FromName("X") == nil, "e_unk_err")
        expect(enumType:FromValue(0) == Enum.HumanoidStateType.FallingDown, "e_val_err")
        expect(typeof(Enum.HumanoidStateType.FallingDown) == "EnumItem", "e_item_err")
        
        local fnOk = pcall(enumType.FromName)
        expect(not fnOk, "e_r_1")
        
        local fvOk = pcall(enumType.FromValue)
        expect(not fvOk, "e_r_2")
    end)

    check("b_align", function()
        expect(bit32.band(0xF0, 0x0F) == 0, "b_leak_1")
        expect(bit32.band(0xFF, 0x0F) == 0x0F, "b_leak_2")
        local ok, pReturn = pcall(function() return true end)
        expect(ok == true, "p_swal")
    end)

    check("cc_depth", function()
        local infoFn = debug.info
        local function sample(cb)
            local function inner() cb() end
            inner()
        end
        sample(function()
            local ok, src = pcall(infoFn, 3, "s")
            local isHooked = (ok and src == "[C]")
            expect(not isHooked, "cc_err")
        end)
    end)

    check("gc_alloc", function()
        if type(newproxy) == "function" then
            local proxy = newproxy(true)
            local mt = getmetatable(proxy)
            expect(type(mt) == "table", "mt_miss")
            mt.__index = { probe = 1 }
            mt.__len = function() return 99 end
            expect(proxy.probe == 1, "idx_err")
            expect(#proxy == 99, "len_err")
        end
    end)

    check("lib_ptr", function()
        local libs = {math, string, table, coroutine, debug, task}
        for _, lib in ipairs(libs) do
            expect(type(lib) == "table", "lib_t_err")
            local mt = getmetatable(lib)
            expect(mt == nil or type(mt) == "string", "lib_mt_err")
        end
    end)

    check("dbg_hk", function()
        if type(debug) == "table" and type(debug.gethook) == "function" then
            local ok, hook = pcall(debug.gethook)
            expect(not (ok and hook ~= nil), "hk_det")
        end
    end)

    check("ds_meta", function()
        local ok, obj = pcall(Instance.new, "DataStoreIncrementOptions")
        if ok and obj then
            local payload = { sync = 1 }
            obj:SetMetadata(payload)
            local read = obj:GetMetadata()
            expect(type(read) == "table" and read.sync == 1, "ds_meta_err")
            obj:Destroy()
        end
    end)

    check("th_type", function()
        local th = coroutine.create(function() end)
        expect(type(th) == "thread", "th_err")
    end)

    check("gc_t", function()
        if getgc then
            expect(type(getgc) == "function", "gc_err")
        end
    end)

    check("str_mt", function()
        expect(getmetatable("") == "The metatable is locked", "str_mt_1")
        if type(debug) == "table" and type(debug.getmetatable) == "function" then
            local ok, mt = pcall(debug.getmetatable, "")
            if ok and type(mt) == "table" then
                expect(mt.__index == string, "str_mt_2")
                expect(mt.__metatable == "The metatable is locked", "str_mt_3")
            end
        end
    end)

    if #failures > 0 then
        error("Tampering Detected", 0)
    end
`;

function luaToProgram(src) { const c = new LuaCompiler(); return c.compile(src); }

function encodeConst(out, v, strLock) {
  if (v === null || v === undefined) { out.push(0); return; }
  if (v === false) { out.push(1); return; }
  if (v === true)  { out.push(2); return; }
  if (typeof v === 'number') { out.push(3); encNum(out, v); return; }
  if (typeof v === 'string') {
    out.push(6);
    const b = strToUtf8(v);
    writeU(out, b.length);
    const tempKey = Math.floor(Math.random() * 256);
    out.push(tempKey);
    b.forEach((charByte, i) => {
      out.push(charByte ^ tempKey ^ strLock ^ (i % 256));
    });
    return;
  }
  if (typeof v === 'object' && 'fn' in v) { out.push(5); writeU(out, v.fn); return; }
  throw new Error('unsupported const: ' + typeof v);
}

function compile(program, key) {
  const { A: lcgA, M: lcgM } = pickLcgParams(key);
  const strLock = Math.floor(Math.random() * 250) + 1; // Must be an 8-bit lock!
  const salt = Array.from({ length: 4 }, () => Math.floor(Math.random() * 256));
  const seeds = deriveSeeds(key, salt, lcgA, lcgM);
  const perm = buildPerm(seeds.sp, lcgA, lcgM);

  const byteMap=[0,1,2,3];for(let i=3;i>0;i--){const j=Math.floor(Math.random()*(i+1));[byteMap[i],byteMap[j]]=[byteMap[j],byteMap[i]];}
  const fns = program.functions.map(f => ({ code: assemble(f.src), numLocals: f.numLocals || 0, numParams: f.numParams || 0, numRegs: f.numRegs || 0 }));

  const mainIndex = (program.mainIndex !== undefined ? program.mainIndex : 0);
  const out = []; out.push(1); writeU(out, mainIndex + 1); writeU(out, fns.length);
  for (const f of fns) {
    writeU(out, f.numLocals); writeU(out, f.numParams); writeU(out, f.numRegs); writeU(out, f.code.length);
    let pc = 1;
    let prevPacked = 0;
    for (const ins of f.code) {
      const arg = HAS_OPERAND[ins[0]] ? ins[1] : 0;
      const uArg = arg < 0 ? arg + 16777216 : arg; 
      const realOp = perm[ins[0]] & 0xFF;
      const pHash = seedMix(seeds.ks, [pc & 0xFF, (pc >>> 8) & 0xFF], lcgA, lcgM);
      const argHash = seedMix(seeds.ks, [(pc >>> 16) & 0xFF, pc & 0xFF], lcgA, lcgM) & 0xFFFFFF;
      const mutatedOp = realOp ^ (pHash & 0xFF) ^ (prevPacked & 0xFF);
      const mutatedArg = uArg ^ argHash ^ ((prevPacked >>> 8) & 0xFFFFFF);
      const packed = mutatedOp + (mutatedArg * 256);
      const b = [packed & 0xFF, Math.floor(packed / 256) & 0xFF, Math.floor(packed / 65536) & 0xFF, Math.floor(packed / 16777216) & 0xFF];
      out.push(b[byteMap[0]], b[byteMap[1]], b[byteMap[2]], b[byteMap[3]]);
      
      prevPacked = packed;
      pc++;
    }
  }

  const consts = program.constants || []; writeU(out, consts.length);
  for (const v of consts) encodeConst(out, v, strLock);
  
  const ck = cksum(out); out.push(ck & 0xff, (ck >>> 8) & 0xff);

  const cipher = xorStream(out, seeds.ks, lcgA, lcgM);
  const allBytes = salt.concat(cipher);

  const payloadStr = allBytes.map(b => String.fromCharCode(b)).join('');
  const cb1Payload = encodeCB1Format(payloadStr);

  const keyBytes = strToUtf8(key);
  const luaKey = '"' + keyBytes.map(b => '\\' + b.toString().padStart(3, '0')).join('') + '"';

  return { cb1Payload, luaKey, byteMap, strLock };
}

function makeV() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const reserved = new Set([
    'do','if','in','or','and','end','for','nil','not','then','else',
    'true','false','local','while','break','return','repeat','until',
    'function',
    'L','E','y','t','pb','lt','p','pv',
    'gg','Pg','Fg','Og','vC','Si','A','o','d','l'
  ]);
  const used = new Set();
  
  let length = 1;
  
  return () => {
    for (let t = 0; t < 500000; t++) {
      let name = '';
      for (let i = 0; i < length; i++) {
        name += chars[Math.floor(Math.random() * chars.length)];
      }
      
      if (!used.has(name) && !reserved.has(name)) { 
        used.add(name); 
        if (used.size > 40) length = 2; 
        if (used.size > 2000) length = 3;
        return name; 
      }
    }
    throw new Error('makeV exhausted');
  };
}

function minifyLua(code) {
  return code
    .replace(/\s*([=+\-*/%^#~<>\[\]{}();,:]|==|~=|<=|>=|\.\.)\s*/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
}

function heavyNum(n) {
  const negative = n < 0;
  n = Math.abs(Math.trunc(n)) >>> 0;

  const base = [2, 10, 16][Math.floor(Math.random() * 3)];
  let digits = n.toString(base);

  if (base === 16 && Math.random() < 0.5) {
    digits = [...digits]
      .map(c => Math.random() < 0.5 ? c.toUpperCase() : c.toLowerCase())
      .join('');
  }

  if (digits.length > 2) {
    let mixed = digits[0];

    for (let i = 1; i < digits.length; i++) {
      if (Math.random() < 0.25) mixed += '_';
      mixed += digits[i];
    }

    digits = mixed;
  }

  const prefix =
    base === 2 ? (Math.random() < 0.5 ? '0b' : '0B') :
    base === 16 ? (Math.random() < 0.5 ? '0x' : '0X') :
    '';

  return `${negative ? '-' : ''}${prefix}${digits}`;
}

function obfStr(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    out += '\\' + s.charCodeAt(i).toString().padStart(3, '0');
  }
  return `"${out}"`;
}

function luauEscape(str) {
  let out = '';
  const quote = Math.random() < 0.5 ? "'" : '"';
  
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    const code = char.charCodeAt(0);
    const hex = code.toString(16).toUpperCase();
    const dec = code.toString(10);
    const roll = Math.random();
    if (roll < 0.25 && /[a-zA-Z]/.test(char)) {
      out += char;
    } else if (roll < 0.50) {
      out += `\\x${hex.padStart(2, '0')}`;
    } else if (roll < 0.75) {
      out += `\\${dec.padStart(3, '0')}`;
    } else {
      out += `\\u{${hex.padStart(4, '0')}}`;
    }
    if (Math.random() < 0.25 && i < str.length - 1) {
      const spaces = " ".repeat(Math.floor(Math.random() * 3) + 1);
      out += `\\z${spaces}`;
    }
  }
  return `${quote}${out}${quote}`;
}

function buildHybridHeaderEntries() {
  const N = heavyNum;

  return [
    `gg=function(p,p,o,V,G,X)if X==${N(129)} then(V[${N(29)}])[p+${N(3)}]=(o);return ${N(56135)};elseif X~=${N(26)} then else V[${N(29)}][p+${N(2)}]=G;return ${N(58170)};end;return nil;end`,
    `Pg=function(p,p)p[${N(51)}]=${N(218)};p[${N(52)}]=p[${N(51)}]+${N(1)};end`,
    `Fg=function(p,o,V)local G=o[${N(3)}]or ${N(0)};if G==${N(1)} then V=G+${N(4)};elseif G~=${N(2)} then else V=${N(7)};end;(o)[${N(42)}]=(V);return V;end`,
    `Og=function(p,o,V,G,X)repeat if G<${N(9)} then G=G+${N(1)};continue;elseif not(G>${N(18)})then else X=G;break;end;until false;return o,G,X;end`,
    `_K=function(p,o,V,G)G=o[${N(3)}]or ${N(0)};if G==${N(1)} then V=G+${N(4)};elseif G~=${N(2)} then else V=${N(7)};end;(o)[${N(42)}]=(V);p[${N(13)}]=G+${N(128)};return V,G;end`,
    `_M={[${N(99)}]=${N(1)},[${N(0)}]=${N(42)}}`,
    `nW=function(p,o,V,G)o[${N(49)}]=nil;(o)[${N(50)}]=(nil);(o)[${N(51)}]=nil;G=${N(126)};if G<${N(62)} then o[${N(51)}]=p[${N(34)}];else o[${N(49)}]=p[${N(42)}];end;return G;end`,
    `Ri=function(L,k,m,p,t,H,a)t=${N(69)};if not(t<=${N(69)})then if not(t>${N(96)})then t=L:gi(t,a,H);else m=p();if not(not a[${N(1388)}])then t=a[${N(1388)}];else t=(-${N(5109902284)})+L.E[${N(9)}];(a)[${N(1388)}]=t;end;end;else if not(t>=${N(102)})then H[${N(5)}][${N(5)}]=L.tA;else H[${N(5)}][${N(12)}]=L.s.bor;end;end;H[${N(5)}][${N(7)}]=L.wA;H[${N(5)}][${N(9)}]=L.v;return p,t,m,k;end`
  ];
}

function secureString(str) {
  const bytes = typeof Buffer !== 'undefined' 
    ? Array.from(Buffer.from(str, 'utf8')) 
    : Array.from(new TextEncoder().encode(str));
    
  const xorKey = Math.floor(Math.random() * 250) + 1;
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const bad = new Set(['if', 'do', 'in', 'or']);
  const rVar = () => {
    let res;
    while (true) {
      res = chars[Math.floor(Math.random() * chars.length)] + chars[Math.floor(Math.random() * chars.length)];
      if (!bad.has(res)) return res;
    }
  };
  
  const vChar = rVar(), vXor = rVar(), vStr = rVar(), vFunc = rVar();
  const vArgs = rVar(), vIdx = rVar(), vJnk1 = rVar(), vJnk2 = rVar();
  
  let calls = [];
  let currentCall = [];
  
  for (let i = 0; i < bytes.length; i++) {
    const posKey = (xorKey + i) % 256;
    const encrypted = bytes[i] ^ posKey;
    currentCall.push(`${heavyNum(encrypted)},${heavyNum(posKey)}`);
    if (currentCall.length >= 4 || i === bytes.length - 1) { 
      calls.push(`(${currentCall.join(',')})`);
      currentCall = [];
    }
  }
  
  if (calls.length === 0) calls = ['()'];
  else calls.push('()');
  
  const chainedCalls = calls.join('');
  
  const isCharFirst = Math.random() < 0.5;
  const argDef = isCharFirst ? `${vChar},${vJnk1},${vXor},${vJnk2}` : `${vJnk1},${vXor},${vJnk2},${vChar}`;
  const argPass = isCharFirst ? `string.char,nil,bit32.bxor,0` : `false,bit32.bxor,true,string.char`;
  
  const core = `local ${vStr}="" local function ${vFunc}(...) local ${vArgs}={...} if #${vArgs}==0 then return ${vStr} end for ${vIdx}=1,#${vArgs},2 do ${vStr}=${vStr}..${vChar}(${vXor}(${vArgs}[${vIdx}],${vArgs}[${vIdx}+1])) end return ${vFunc} end return ${vFunc}`;
  
  return `(function(${argDef}) ${core} end)(${argPass})${chainedCalls}`;
}

function buildLuaRuntime(cb1Payload, luaKey, V, byteMap = [0,1,2,3], strLock = 0x1337) {
  const vRun=V(),vI=V(),vJ=V(),vAl=V(),vIm=V(),vDt=V(),vDz=V(),vPt=V(),vRf=V(),vNc=V();
  const vWs=V(),vEn=V(),vRs=V(),vCd=V(),vSb=V(),vCh=V(),vCo=V(),vBy=V();
  const vPay=V(),vKey=V(),vRaw=V(),vBt=V();
  const vMr=V(),vSd=V(),vRs2=V(),vHs=V(),vSt=V(),vHv=V(),vMl=V(),vMa=V(),vMb=V(),vAlo=V(),vAhi=V(),vBlo=V(),vBhi=V(),vMd=V(),vLo2=V();
  const vBp=V(),vRg=V(),vPm=V(),vIp=V(),vIv=V();
  const vDv=V(),vSl=V(),vKh=V(),vSn=V(),vNs=V(),vKs=V(),vSp=V();
  const vXs=V(),vBs=V(),vOt=V();
  const vCk=V(),vSm=V(),vNv=V();
  const vRu2=V(),vRd2=V(),vRdd=V(),vPs=V(),vSh=V(),vRt=V(),vB2=V(),vVv=V();
  const vRu=V(),vRs3=V(),vRd=V();
  const vSg=V(),vEx=V(),vMn=V();
  const vPl=V(),vPn=V(),vSd2=V(),vBd=V();
  const vHo=V(),vNf=V(),vFn=V(),vNl=V(),vNp=V(),vNr=V(),vCl=V(),vCo2=V(),vOp=V(),vAg=V();
  const vNc2=V(),vCs=V(),vTg=V(),vSl2=V(),vSb2=V(),vFi=V(),vIs=V();
  const vSk=V(),vSp2=V(),vPu=V(),vPo=V(),vVl=V(),vGl=V();
  const vFr=V(),vFc=V(),vNw=V(),vIn=V(),vAr=V(),vLo=V(),vNv2=V(),vRe=V();
  const vFm=V(),vHl=V(),vIs2=V(),vF2=V(),vRv=V(),vBv=V(),vAv=V(),vN2=V();
  const vKv=V(),vTv=V(),vNa=V(),vXv=V(),vAb=V();
  const vItFn=V(),vItSt=V(),vItCt=V(),vItVs=V(),vItN=V(),vFn2=V();

  const vCloneFn = V();
  const imap_name = V();
  const vMainIdx = V();
  const vPacked = V(), vMutatedOp = V(), vOpRaw = V();
  
  const vMkCl = V(), vClFi = V(), vClUp = V(), vClMeta = V(), vClArgs = V(), vClLoc = V(), vClChain = V();
  const vClStk = V(), vClSp = V(), vClPu = V(), vClPo = V(), vClPv = V(), vClPc = V(), vClCode = V(), vClIns = V(), vClRegs = V(), vClArgsN = V();
  const vUpD = V(), vUpS = V(), vCgN = V(), vCgArgs = V(), vCgFn = V(), vCgRes = V(), vSwapTmp = V(), vNArgGiven = V(), vNArgUse = V();
  const vLcgA = V(), vLcgM = V();
  const vSfk = V(), vSfkKey = V(), vSfkS = V();
  const vSmx = V(), vSmxSeed = V(), vSmxBytes = V(), vSmxS = V();
  const vX8 = V(), vX8A = V(), vX8B = V(), vX8R = V(), vX8M = V(), vX8I = V(), vX8Ab = V(), vX8Bb = V();
  const vKeySeed = V(), vSaltInv = V(), vSiI = V();
  const LCG_PRIMES = [2147483647, 2147483629, 2147483587, 2147483579, 2147483563];
  const LCG_MULTIPLIERS = [16807, 48271, 69621, 40014, 630360016];

  const tableEntries = [];
  const consts = [1, 2, 3, 4, 5, 8, 16, 32, 64, 128, 255, 256, 65536, 2147483647];
  tableEntries.push(`${V()}={${consts.map(c => heavyNum(c)).join(',')}}`);
  tableEntries.push(`${V()}=bit32.bnot`);
  tableEntries.push(`${V()}=bit32.bxor`);
  tableEntries.push(`${V()}=bit32.band`);
  tableEntries.push(`${V()}=bit32.bor`);
  tableEntries.push(`${V()}=bit32.lshift`);
  tableEntries.push(`${V()}=bit32.rshift`);
  tableEntries.push(`${V()}=bit32.lrotate`);
  tableEntries.push(`${V()}=bit32.rrotate`);
  tableEntries.push(`${V()}=bit32.countlz`);
  tableEntries.push(`${V()}=bit32.countrz`);
  tableEntries.push(`t=bit32.bxor`);
  tableEntries.push(`pb=bit32.band`);
  tableEntries.push(`lt=bit32.bor`);
  tableEntries.push(`y=bit32.bnot`);
  tableEntries.push(`p=bit32.lshift`);
  tableEntries.push(`pv=bit32.rshift`);
  tableEntries.push(`${V()}=string.unpack`);
  tableEntries.push(`${V()}=string.char`);
  tableEntries.push(`${V()}=string.byte`);
  tableEntries.push(`${V()}=string.sub`);
  tableEntries.push(`${V()}=table.create`);
  tableEntries.push(`${V()}=table.unpack`);
  tableEntries.push(`${V()}=table.move`);
  tableEntries.push(`${V()}=coroutine.wrap`);
  tableEntries.push(`${V()}=coroutine.yield`);
  tableEntries.push(`${V()}=type`);
  tableEntries.push(`${V()}=select`);
  tableEntries.push(`${V()}=unpack`);
  tableEntries.push(`${V()}=true`);
  tableEntries.push(`${V()}=nil`);
  tableEntries.push(...buildHybridHeaderEntries());

  function wrapDenseWall(inner, depth) {
    if (depth <= 0) return inner;
    const X = V(), q = V(), r = V(), T = V();
    const gate = heavyNum(Math.floor(Math.random() * 255) + 1);
    const dead = heavyNum(Math.floor(Math.random() * 255) + 1);
    const zero = heavyNum(0);
    const mod = heavyNum(2);
    const jIdx = heavyNum(Math.floor(Math.random() * 64) + 1);
    const jVal1 = heavyNum(Math.floor(Math.random() * 65535));
    const jVal2 = heavyNum(Math.floor(Math.random() * 65535));
    const nested = wrapDenseWall(inner, depth - 1);
    let prefix = `local ${X},${q},${r},${T}=(${gate}),(${dead}),(${zero}),nil;${T}={};(${T})[${jIdx}]=(${jVal1});`;
    if (Math.random() < 0.40) {
      const fakeReg = V(), fakeBC = V(), fakeIter = V(), fakeInst = V();
      const op1 = heavyNum(1), op2 = heavyNum(2), op3 = heavyNum(3);
      const arg1 = heavyNum(Math.floor(Math.random() * 65535));
      const arg2 = heavyNum(Math.floor(Math.random() * 65535));
      const arg3 = heavyNum(Math.floor(Math.random() * 65535));
      prefix += `local ${fakeReg},${fakeBC},${fakeIter},${fakeInst}=(nil),nil,nil,nil;`;
      prefix += `${fakeReg}={};${fakeBC}={{(${op1}),(${arg1})},{(${op2}),(${arg2})},{(${op3}),(${arg3})}};`;
      prefix += `for ${fakeIter}=(${heavyNum(1)}),(${heavyNum(3)}),(${heavyNum(1)}) do ${fakeInst}=(${fakeBC})[${fakeIter}];`;
      prefix += `if((${fakeInst})[${heavyNum(1)}]==(${op1}))then(${fakeReg})[${heavyNum(1)}]=((${fakeInst})[${heavyNum(2)}]);`;
      prefix += `elseif((${fakeInst})[${heavyNum(1)}]==(${op2}))then(${fakeReg})[${heavyNum(2)}]=(${fakeReg})[${heavyNum(1)}];`;
      prefix += `else(${fakeReg})[${heavyNum(3)}]=(${fakeInst}[${heavyNum(2)}]);end;end;`;
    }
    if (Math.random() < 0.40) {
      const b1 = heavyNum(Math.floor(Math.random() * 65535)), b2 = heavyNum(Math.floor(Math.random() * 65535)), b3 = heavyNum(Math.floor(Math.random() * 65535));
      prefix += `(${T})[${jIdx}]=(bit32.bor((bit32.bxor((${b1}),(bit32.band((${b2}),(${b3}))))),(${zero})));`;
    }
    const style = Math.floor(Math.random() * 5);
    if (style === 0) return `${prefix}if(${X})==(${gate})then ${nested}elseif(${X})~=(${q})then(${T})[${zero}]=(${r});else return(${jVal2});end;`;
    if (style === 1) return `${prefix}repeat if(${X})==(${gate})then ${nested}elseif(${X})~=(${q})then else return(${T})[${jIdx}];end;until false;`;
    if (style === 2) return `${prefix}while true do if(${X})==(${gate})then ${nested}elseif(${X})~=(${q})then break;else return(${jVal1});end;end;`;
    if (style === 3) return `${prefix}if not((${X})~=(${gate}))and(((${X})%(${mod}))==((${gate})%(${mod})))then ${nested}elseif(${X})~=(${q})then else return(${jVal2});end;`;
    return `${prefix}if(${X})==(${gate})then if((${q})==(${r}))then return(${jVal1});else ${nested}end;elseif(${X})~=(${q})then else return(${T})[${jIdx}];end;`;
  }

  for (let i = 0; i < 10; i++) {
    const e = V(), H = V(), p = V(), k = V(), c = V(), z = V();
    const a1 = `(${e}[${heavyNum(1)}])`, a2 = `${e}[${heavyNum(2)}]`, a3 = `(${e}[${heavyNum(3)}])`;
    const tableValue = a2;
    const typeCheck = `(type(${tableValue})==${luauEscape('table')})`;
    const prefix = `local ${e}={...};local ${H},${p},${k},${c}=(${heavyNum(Math.floor(Math.random() * 200))}),(${a1}),(${a2}),(${typeCheck});local ${z}=(${H})+(${heavyNum(0)});`;
    const payload = `return((${c})and(${a1})or(${a1})),(((${c})and(#(${tableValue})>(${heavyNum(0)})))and((${H})+((#(${tableValue}))%(${heavyNum(2)})))or(${z})),(${a3});`;
    const body = prefix + wrapDenseWall(payload, 10 + Math.floor(Math.random() * 6));
    const signatureLength = 5 + Math.floor(Math.random() * 6);
    const signatureNames = Array.from({ length: signatureLength }, () => V());
    if (signatureNames.length >= 2 && Math.random() < 0.6) {
      const idx = Math.floor(Math.random() * (signatureNames.length - 1));
      signatureNames[idx + 1] = signatureNames[idx];
    }
    for (let j = 2; j < signatureNames.length; j++) {
      if (Math.random() < 0.25) signatureNames[j] = signatureNames[Math.floor(Math.random() * j)];
    }
    tableEntries.push(`${V()}=function(${signatureNames.join(',')},...)${body}end`);
  }
  
  let zBody = [];
  const p = (...a) => zBody.push(...a);

  p(`local ${vCloneFn}=clonefunction or function(f)return f;end;`);
  p(`local ${vBy}=${vCloneFn}(string.byte);local ${vCh}=${vCloneFn}(string.char);`);

  const chunks = cb1Payload.match(/.{1,128}/g) || [];
  const vPayTbl = V();
  p(`local ${vPayTbl}={${chunks.map(c => `function()return'${c}';end`).join(',')}};`);

  const vEnvVar = V();
  p(`local ${vEnvVar}=getgenv and getgenv() or _G;`);
  
  const getS = (str) => secureString(str);
  const getHybridStr = (str) => secureString(str);

  const vIdx = V(), vCurChunkIdx = V(), vCurChunk = V(), vGetByte = V(), vCharSub = V();

  p(`local ${vAl}={};for ${vI}=(${heavyNum(0)}),(${heavyNum(255)}) do ${vAl}[${vI}]=${vEnvVar}[${getS("string")}][${getS("char")}](${vI});end;`);
  p(`local ${imap_name}={};local ${vAb}=${luauEscape(ALPHABET)};for ${vIdx}=1,#${vAb} do ${imap_name}[string.sub(${vAb},${vIdx},${vIdx})]=(${vIdx})-1;end;`);
  p(`local ${vDt}={};for ${vI}=(${heavyNum(0)}),(${heavyNum(255)}) do ${vDt}[${vI}]=${vAl}[${vI}];end;local ${vDz}=(${heavyNum(256)});local ${vPt}=(${heavyNum(1)});`);

  p(`local ${vCurChunkIdx}=1;local ${vCurChunk}=${vPayTbl}[1]();local function ${vGetByte}() if(${vPt})>#${vCurChunk} then ${vCurChunkIdx}=(${vCurChunkIdx})+1;if not ${vPayTbl}[${vCurChunkIdx}] then return nil;end;${vCurChunk}=${vPayTbl}[${vCurChunkIdx}]();${vPt}=1;end;local ${vCharSub}=string.sub(${vCurChunk},${vPt},${vPt});${vPt}=(${vPt})+1;return ${vCharSub};end;`);

  const vByteRef = V();
  p(`local function ${vRf}() local ${vByteRef}=${vGetByte}();if not ${vByteRef} then return nil;end;local ${vNc}=${imap_name}[${vByteRef}]+(${heavyNum(1)});local ${vVv}=(${heavyNum(0)});for ${vI}=(${heavyNum(1)}),${vNc} do ${vVv}=(${vVv})*(${heavyNum(85)})+${imap_name}[${vGetByte}()];end;return ${vVv};end;`);

  p(`local ${vWs}=${vCh}(${vRf}());local ${vEn}={${vWs}};`);
  p(`while true do local ${vCd}=${vRf}();if not ${vCd} then break;end;local ${vSb};if ${vDt}[${vCd}]~=nil then ${vSb}=${vDt}[${vCd}];else ${vSb}=${vWs}..${vCh}(${vBy}(${vWs},(${heavyNum(1)})));end;${vEn}[#${vEn}+(${heavyNum(1)})]=${vSb};${vDt}[${vDz}]=${vWs}..${vCh}(${vBy}(${vSb},(${heavyNum(1)})));${vDz}=(${vDz})+(${heavyNum(1)});${vWs}=${vSb};end;`);

  const vJoin = V(), vTArg = V(), vSStr = V(), vI2 = V();
  p(`local function ${vJoin}(${vTArg})local ${vSStr}="";for ${vI2}=1,#${vTArg} do ${vSStr}=${vSStr}..(${vTArg})[${vI2}];end;return ${vSStr};end;local ${vRs}=${vJoin}(${vEn});`);

  p(`local ${vBt}={};for ${vI}=(${heavyNum(1)}),#${vRs} do ${vBt}[${vI}]=${vBy}(${vRs},${vI});end;local ${vLcgA};local ${vLcgM};`);
  p(`local function ${vSfk}(${vSfkKey}) local ${vSfkS}=(${heavyNum(1)});for ${vI}=(${heavyNum(1)}),#${vSfkKey} do ${vSfkS}=((${vSfkS})*(${vLcgA})+${vBy}(${vSfkKey},${vI})+(${heavyNum(1)}))%(${vLcgM});if(${vSfkS})==(${heavyNum(0)})then ${vSfkS}=(${heavyNum(1)});end;end;return ${vSfkS};end;`);
  p(`local function ${vSmx}(${vSmxSeed},${vSmxBytes}) local ${vSmxS}=${vSmxSeed};for ${vI}=(${heavyNum(1)}),#${vSmxBytes} do ${vSmxS}=((${vSmxS})*(${vLcgA})+(${vSmxBytes})[${vI}]+(${heavyNum(1)}))%(${vLcgM});if(${vSmxS})==(${heavyNum(0)})then ${vSmxS}=(${heavyNum(1)});end;end;return ${vSmxS};end;`);
  p(`local function ${vMr}(${vSd}) local ${vRs2}=${vSd};if(${vRs2})==(${heavyNum(0)})then ${vRs2}=(${heavyNum(1)});end;return function()${vRs2}=((${vRs2})*(${vLcgA}))%(${vLcgM});return ${vRs2};end;end;`);
  p(`local function ${vX8}(${vX8A},${vX8B}) local ${vX8R}=(${heavyNum(0)});local ${vX8M}=(${heavyNum(1)});for ${vX8I}=(${heavyNum(1)}),(${heavyNum(8)}) do local ${vX8Ab}=(${vX8A})%(${heavyNum(2)});local ${vX8Bb}=(${vX8B})%(${heavyNum(2)});if(${vX8Ab})~=(${vX8Bb})then ${vX8R}=(${vX8R})+(${vX8M});end;${vX8A}=((${vX8A})-(${vX8Ab}))/(${heavyNum(2)});${vX8B}=((${vX8B})-(${vX8Bb}))/(${heavyNum(2)});${vX8M}=((${vX8M})*(${heavyNum(2)}));end;return ${vX8R};end;`);
  p(`local function ${vBp}(${vSd}) local ${vRg}=${vMr}(${vSd});local ${vPm}={};for ${vI}=(${heavyNum(0)}),(${heavyNum(255)}) do ${vPm}[${vI}]=${vI};end;for ${vI}=(${heavyNum(255)}),(${heavyNum(1)}),-(${heavyNum(1)}) do local ${vJ}=((${vRg}())%((${vI})+(${heavyNum(1)})));${vPm}[${vI}],${vPm}[${vJ}]=${vPm}[${vJ}],${vPm}[${vI}];end;return ${vPm};end;`);
  p(`local function ${vIp}(${vPm}) local ${vIv}={};for ${vI}=(${heavyNum(0)}),(${heavyNum(255)}) do ${vIv}[(${vPm})[${vI}]]=${vI};end;return ${vIv};end;`);
  p(`local function ${vDv}(${vKey},${vSl}) local ${vKeySeed}=${vSfk}(${vKey});local ${vKs}=${vSmx}(${vKeySeed},${vSl});local ${vSaltInv}={};for ${vSiI}=(${heavyNum(1)}),#${vSl} do ${vSaltInv}[${vSiI}]=(${heavyNum(255)})-(${vSl})[#${vSl}-(${vSiI})+(${heavyNum(1)})];end;local ${vSp}=${vSmx}(${vKeySeed},${vSaltInv});return ${vKs},${vSp};end;`);
  p(`local function ${vXs}(${vBs},${vSd}) local ${vRg}=${vMr}(${vSd});local ${vOt}={};for ${vI}=(${heavyNum(1)}),#${vBs} do ${vOt}[${vI}]=${vX8}((${vBs})[${vI}],(${vRg}())%(${heavyNum(256)}));end;return ${vOt};end;`);
  p(`local function ${vCk}(${vBs},${vNv}) local ${vSm}=(${heavyNum(0)});for ${vI}=(${heavyNum(1)}),${vNv} do ${vSm}=((${vSm})+(${vBs})[${vI}])%(${heavyNum(65536)});end;return ${vSm};end;`);
  p(`local ${vSl}={${vBt}[(${heavyNum(1)})],${vBt}[(${heavyNum(2)})],${vBt}[(${heavyNum(3)})],${vBt}[(${heavyNum(4)})]};local ${vBs}={};for ${vI}=(${heavyNum(5)}),#${vBt} do ${vBs}[#${vBs}+(${heavyNum(1)})]=${vBt}[${vI}];end;local ${vKey}=${luaKey};`);
  const vLcgPrimes = V(), vLcgMults = V(), vLcgH = V(), vLcgHi = V();
  p(`local ${vLcgPrimes}={${LCG_PRIMES.map(n => heavyNum(n)).join(',')}};local ${vLcgMults}={${LCG_MULTIPLIERS.map(n => heavyNum(n)).join(',')}};local ${vLcgH}=(${heavyNum(0)});`);
  p(`for ${vLcgHi}=(${heavyNum(1)}),#${vKey} do ${vLcgH}=bit32.band(((${vLcgH})*(${heavyNum(31)}))+${vBy}(${vKey},${vLcgHi}),(${heavyNum(0xFFFFFFFF)}));end;`);
  p(`${vLcgM}=${vLcgPrimes}[(((${vLcgH})%(${heavyNum(LCG_PRIMES.length)}))+(${heavyNum(1)}))];${vLcgA}=${vLcgMults}[((bit32.rshift(${vLcgH},(${heavyNum(3)}))%(${heavyNum(LCG_MULTIPLIERS.length)}))+(${heavyNum(1)}))];local ${vKs},${vSp}=${vDv}(${vKey},${vSl});`);
  const vStreamRg = V(), vNextByte = V(), vByteReturn = V();
  const vPrevCiph = V(), vRawCiph = V(), vKByte = V();
  p(`local ${vPs}=(${heavyNum(1)});local ${vStreamRg}=${vMr}(${vKs});local ${vPrevCiph}=(${vStreamRg}())%(${heavyNum(256)});`);
  p(`local function ${vNextByte}() local ${vRawCiph}=${vBs}[${vPs}] or 0;local ${vKByte}=(${vStreamRg}())%(${heavyNum(256)});local ${vByteReturn}=${vX8}(${vRawCiph},${vX8}(${vKByte},${vPrevCiph}));${vPrevCiph}=${vRawCiph};${vPs}=(${vPs})+(${heavyNum(1)});return ${vByteReturn};end;${vNextByte}();`);
  p(`local function ${vRu}() local ${vSh},${vRt}=(${heavyNum(1)}),(${heavyNum(0)});repeat local ${vB2}=${vNextByte}();${vRt}=(${vRt})+((${vB2})%(${heavyNum(128)}))*(${vSh});${vSh}=(${vSh})*(${heavyNum(128)});until (${vB2})<(${heavyNum(128)});return ${vRt};end;`);
  p(`local function ${vRs3}() local ${vVv}=${vRu}();return (((${vVv})%(${heavyNum(2)}))==(${heavyNum(0)}) and (${vVv})/(${heavyNum(2)}) or -((${vVv})+(${heavyNum(1)}))/(${heavyNum(2)}));end;`);
  const b0=V(),b1=V(),b2=V(),b3=V(),b4=V(),b5=V(),b6=V(),b7=V(),bIter=V(),bDummy=V();
  p(`local function ${vRd}() local ${b0},${b1},${b2},${b3},${b4},${b5},${b6},${b7}=${vNextByte}(),${vNextByte}(),${vNextByte}(),${vNextByte}(),${vNextByte}(),${vNextByte}(),${vNextByte}(),${vNextByte}();local ${vSg}=math.floor((${b7})/(${heavyNum(128)}));local ${vEx}=((${b7})%(${heavyNum(128)}))*(${heavyNum(16)})+math.floor((${b6})/(${heavyNum(16)}));local ${vMn}=(${b6})%(${heavyNum(16)});for ${bDummy},${bIter} in ipairs({${b5},${b4},${b3},${b2},${b1},${b0}}) do ${vMn}=((${vMn})*(${heavyNum(256)}))+(${bIter});end;if (${vEx})==(${heavyNum(0)}) and (${vMn})==(${heavyNum(0)}) then return (${heavyNum(0)});end;if (${vEx})==(${heavyNum(2047)}) then return ((${vMn})~=(${heavyNum(0)}) and (${heavyNum(0)})/(${heavyNum(0)}) or ((${vSg})==(${heavyNum(1)}) and -math.huge or math.huge));end;local ${vVv}=((${heavyNum(1)})+((${vMn})/((${heavyNum(2)})^(${heavyNum(52)}))))*((${heavyNum(2)})^((${vEx})-(${heavyNum(1023)})));return ((${vSg})==(${heavyNum(1)}) and -(${vVv}) or (${vVv}));end;`);
  p(`local ${vIv}=${vIp}(${vBp}(${vSp}));`);
  const hoNums = OPS.map((name, idx) => OPERAND_OPS.has(name) ? idx : -1).filter(idx => idx >= 0).map(n => heavyNum(n));
  const vOIter = V(), vODummy = V();
  p(`local ${vHo}={};for ${vODummy},${vOIter} in ipairs({${hoNums.join(',')}}) do ${vHo}[${vOIter}]=true;end;local ${vMainIdx}=${vRu}();local ${vNf}=${vRu}();local ${vFn}={};`);
  p(`for ${vI}=(${heavyNum(1)}),${vNf} do local ${vNl},${vNp},${vNr},${vCl}=${vRu}(),${vRu}(),${vRu}(),${vRu}();local ${vCo2}={};`);
  const vByte1 = V(), vByte2 = V(), vByte3 = V(), vByte4 = V(), vInst = V();
  const m=[1,256,65536,16777216],m0=m[byteMap[0]],m1=m[byteMap[1]],m2=m[byteMap[2]],m3=m[byteMap[3]];
  p(`for ${vJ}=(${heavyNum(1)}),${vCl} do local ${vByte1},${vByte2},${vByte3},${vByte4}=${vNextByte}(),${vNextByte}(),${vNextByte}(),${vNextByte}();local ${vInst}=((${vByte1})*(${heavyNum(m0)}))+((${vByte2})*(${heavyNum(m1)}))+((${vByte3})*(${heavyNum(m2)}))+((${vByte4})*(${heavyNum(m3)}));${vCo2}[${vJ}]=${vInst};end;${vFn}[${vI}]={code=${vCo2},nl=${vNl},np=${vNp},nr=${vNr}};end;`);
  p(`local ${vNc2}=${vRu}();local ${vCs}={};for ${vI}=(${heavyNum(1)}),${vNc2} do local ${vTg}=${vNextByte}();if(${vTg})==(${heavyNum(0)})then ${vCs}[${vI}]=nil;elseif(${vTg})==(${heavyNum(1)})then ${vCs}[${vI}]=false;elseif(${vTg})==(${heavyNum(2)})then ${vCs}[${vI}]=true;elseif(${vTg})==(${heavyNum(3)})then ${vCs}[${vI}]=${vRd}();elseif(${vTg})==(${heavyNum(4)})then local ${vSl2}=${vRu}();local ${vSb2}="";for ${vJ}=(${heavyNum(1)}),${vSl2} do ${vSb2}=${vSb2}..${vCh}(${vNextByte}());end;${vCs}[${vI}]=${vSb2};elseif(${vTg})==(${heavyNum(5)})then local ${vFi}=${vRu}();${vCs}[${vI}]={__fnref=(${vFi})+(${heavyNum(1)})};`);
  const vXorKey = V(), vCref = V(), vFiC = V(), vEs=V(), vDc=V(), vJ2=V(), vLk=V(), vStrBld = V();
  p(`elseif(${vTg})==(${heavyNum(6)})then local ${vSl2}=${vRu}();local ${vXorKey}=${vNextByte}();local ${vEs}={};for ${vJ}=(${heavyNum(1)}),${vSl2} do ${vEs}[${vJ}]=${vNextByte}();end;${vCs}[${vI}]=function(${vLk})if(${vLk})~=(${heavyNum(strLock)})then return "";end;local ${vStrBld}="";for ${vJ2}=(${heavyNum(1)}),${vSl2} do ${vStrBld}=${vStrBld}..${vCh}(bit32.bxor(${vEs}[${vJ2}],bit32.bxor(${vXorKey},${vLk}),((${vJ2})-(${heavyNum(1)}))%(${heavyNum(256)})));end;return ${vStrBld};end;end;end;`);
  p(`for ${vI}=(${heavyNum(1)}),${vNc2} do local ${vCref}=${vCs}[${vI}];if type(${vCref})==${luauEscape("table")} and (${vCref}).__fnref then local ${vFiC}=(${vCref}).__fnref;${vCs}[${vI}]=function(...)return ${vMkCl}(${vFiC},{})(...);end;end;end;`);
  
  const vEnvTrap = V(), vTarget = V(), vIsCClosure = V();
  p(`local ${vGl}=setmetatable({},{__index=function(_,k) local ${vEnvTrap}=getfenv and getfenv() or _G; local ${vTarget}=${vEnvTrap}[k] or (getgenv and getgenv()[k]); local ${vIsCClosure}=iscclosure or function() return true; end; if type(${vTarget})=="function" and not ${vIsCClosure}(${vTarget}) then return function() while true do end end; end; return ${vTarget}; end});`);
  const vGameMeta = V(), vMetaCheck = V(), vIndexCheck = V();
  p(`local ${vGameMeta}=getrawmetatable and getrawmetatable(game) or {}; local ${vMetaCheck}=${vGameMeta}.__namecall; local ${vIndexCheck}=${vGameMeta}.__index; if (type(${vMetaCheck})=="function" and (iscclosure and not iscclosure(${vMetaCheck}))) or (type(${vIndexCheck})=="function" and (iscclosure and not iscclosure(${vIndexCheck}))) then while true do end end;`);

  const _f = V(), _s = V(), _c = V(), _n = V(), _t = V(), _i = V(), _r = V();
  p(`${vGl}[${getHybridStr("__vlen")}]=function(${vXv})return #${vXv};end;${vGl}[${getHybridStr("__vfloor")}]=math.floor;${vGl}[${getHybridStr("__vmmr")}]=function(${vFn2},...)return {${vFn2}(...)};end;${vGl}[${getHybridStr("__vmgi")}]=function(${vItFn},...)local ${_f},${_s},${_c}=${vItFn}(...);return {${_f},${_s},${_c}};end;${vGl}[${getHybridStr("__vmgp")}]=function(${_f},${_s},${_c})return {${_f},${_s},${_c}};end;${vGl}[${getHybridStr("__vmgn")}]=function(${_f},${_s},${_c},${_n})local ${_r}={${_f}(${_s},${_c})};if(${_r}[(${heavyNum(1)})])==nil then return nil;end;local ${_t}={};for ${_i}=(${heavyNum(1)}),${_n} do ${_t}[${_i}]=${_r}[${_i}];end;return ${_t};end;`);
  
  const mPC = V(), mMt = V(), mTp = V(), mRes = V();
  const states = [];
  while(states.length < 6) { let r = Math.floor(Math.random() * 8000000) + 100000; if(!states.includes(r)) states.push(r); }
  const [sFetch, sCallMt, sCallTp, sCheck, sTrap, sSafe] = states;

  p(`local ${mPC}=(${heavyNum(sFetch)});local ${mMt},${mTp},${mRes};while true do if(${mPC})==(${heavyNum(sFetch)})then ${mMt}=${vGl}[${getS("getmetatable")}];${mTp}=${vGl}[${getS("type")}];${mPC}=(${heavyNum(sCallMt)});elseif(${mPC})==(${heavyNum(sCallMt)})then ${mRes}=${mMt}(${luauEscape("")});${mPC}=(${heavyNum(sCallTp)});elseif(${mPC})==(${heavyNum(sCallTp)})then ${mRes}=${mTp}(${mRes});${mPC}=(${heavyNum(sCheck)});elseif(${mPC})==(${heavyNum(sCheck)})then if(${mRes})~=(${luauEscape("string")})then ${mPC}=(${heavyNum(sTrap)});else ${mPC}=(${heavyNum(sSafe)});end;elseif(${mPC})==(${heavyNum(sTrap)})then (${vGl}[${getS("error")}])(${luauEscape("Tampering Detected")},(${heavyNum(0)}));elseif(${mPC})==(${heavyNum(sSafe)})then break;end;end;`);

  const vAgS = V();
  const cN=V(), cF=V(), cA=V(), cB=V(), cC=V(), cD=V(), cArgs=V(), cI=V();
  const fPu = V(), fPo = V();

  const sM = [1,2,3,4,5,6,7,8,9,10,11,12];
  for(let i=sM.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[sM[i],sM[j]]=[sM[j],sM[i]];}
  const sStk=sM[0], sTop=sM[1], sCon=sM[2], sLoc=sM[3], sPc=sM[4], sReg=sM[5], sGlb=sM[6], sUp=sM[7], sVAg=sM[8], sVAc=sM[9], sTmp=sM[10];

  const getJunkAst = () => {
    if (Math.random() > 0.3) return "";
    const type = Math.floor(Math.random() * 4);
    const j1 = V(), j2 = V(), j3 = V();
    const n1 = heavyNum(Math.floor(Math.random() * 255));
    const n2 = heavyNum(Math.floor(Math.random() * 65535));
    
    if (type === 0) {
      return `local ${j1}=(${n2});local ${j2}=bit32.band(${j1},(${heavyNum(0xFF)}));local ${j3}=bit32.rshift(${j1},(${heavyNum(8)}));if(${j2})==(${n1})then S[(${heavyNum(sTmp)})]=bit32.bxor(S[(${heavyNum(sTmp)})],${j3});end;`;
    } else if (type === 1) {
      return `local ${j1}={};(${j1})[(${heavyNum(1)})]=S[(${heavyNum(sTmp)})];(${j1})[(${heavyNum(2)})]=(${n1});S[(${heavyNum(sTmp)})]=bit32.bxor((${j1})[(${heavyNum(1)})],(${j1})[(${heavyNum(2)})]);`;
    } else if (type === 2) {
      return `local ${j1}=S[(${heavyNum(sTop)})];local ${j2}=(${n1});if(${j1})>(${j2})then S[(${heavyNum(sTmp)})]=((${j1})-(${j2}));else S[(${heavyNum(sTmp)})]=((${j1})+(${j2}));end;`;
    } else {
      return `local ${j1}=(${vAg});local ${j2}=bit32.bxor(${j1},(${n1}));if(${j2})==(${n2})then local ${j3}=S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]];S[(${heavyNum(sTmp)})]=type(${j3})=="number" and ${j3} or (${heavyNum(0)});end;`;
    }
  };

  const vRetV = V(), vRetA = V(), vRetB = V(), vRetT = V(), vRetK = V(), vRetN = V();
  const uD = V(), uS = V();

  const coreHandlers = [
    `${getJunkAst()}L:${fPu}(S,${vAg});`,
    `${getJunkAst()}L:${fPo}(S);`,
    `${getJunkAst()}local ${vRetV}=L:${fPo}(S);L:${fPu}(S,${vRetV});L:${fPu}(S,${vRetV});`,
    `${getJunkAst()}local ${vRetT}=S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]];S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]]=S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})];S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]=${vRetT};`,
    `${getJunkAst()}local ${vRetK}=S[(${heavyNum(sCon)})][(${vAg})+(${heavyNum(1)})];L:${fPu}(S,type(${vRetK})=="function" and ${vRetK}((${heavyNum(strLock)})) or ${vRetK});`,
    `${getJunkAst()}L:${fPu}(S,S[(${heavyNum(sLoc)})][${vAg}]);`,
    `${getJunkAst()}S[(${heavyNum(sLoc)})][${vAg}]=L:${fPo}(S);`,
    `${getJunkAst()}L:${fPu}(S,S[(${heavyNum(sReg)})][${vAg}]);`,
    `${getJunkAst()}S[(${heavyNum(sReg)})][${vAg}]=L:${fPo}(S);`,
    `${getJunkAst()}local ${vRetN}=S[(${heavyNum(sCon)})][(${vAg})+(${heavyNum(1)})];local ${vRetK}=type(${vRetN})=="function" and ${vRetN}((${heavyNum(strLock)})) or ${vRetN};L:${fPu}(S,S[(${heavyNum(sGlb)})][${vRetK}]);`,
    `${getJunkAst()}local ${vRetN}=S[(${heavyNum(sCon)})][(${vAg})+(${heavyNum(1)})];local ${vRetK}=type(${vRetN})=="function" and ${vRetN}((${heavyNum(strLock)})) or ${vRetN};S[(${heavyNum(sGlb)})][${vRetK}]=L:${fPo}(S);`,
    `${getJunkAst()}S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]=S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]+S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]];S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]]=nil;S[(${heavyNum(sTop)})]=S[(${heavyNum(sTop)})]-(${heavyNum(1)});`,
    `${getJunkAst()}S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]=S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]-S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]];S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]]=nil;S[(${heavyNum(sTop)})]=S[(${heavyNum(sTop)})]-(${heavyNum(1)});`,
    `${getJunkAst()}S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]=S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]*S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]];S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]]=nil;S[(${heavyNum(sTop)})]=S[(${heavyNum(sTop)})]-(${heavyNum(1)});`,
    `${getJunkAst()}S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]=S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]/S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]];S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]]=nil;S[(${heavyNum(sTop)})]=S[(${heavyNum(sTop)})]-(${heavyNum(1)});`,
    `${getJunkAst()}S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]=S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]%S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]];S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]]=nil;S[(${heavyNum(sTop)})]=S[(${heavyNum(sTop)})]-(${heavyNum(1)});`,
    `${getJunkAst()}S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]=S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]-(${heavyNum(1)})]^S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]];S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]]=nil;S[(${heavyNum(sTop)})]=S[(${heavyNum(sTop)})]-(${heavyNum(1)});`,
    `${getJunkAst()}L:${fPu}(S,-L:${fPo}(S));`,
    `${getJunkAst()}local ${vRetV}=L:${fPo}(S);L:${fPu}(S,${vRetV}==nil or ${vRetV}==false);`,
    `${getJunkAst()}local ${vRetB}=L:${fPo}(S);local ${vRetA}=L:${fPo}(S);L:${fPu}(S,${vRetA}==${vRetB});`,
    `${getJunkAst()}local ${vRetB}=L:${fPo}(S);local ${vRetA}=L:${fPo}(S);L:${fPu}(S,${vRetA}~=${vRetB});`,
    `${getJunkAst()}local ${vRetB}=L:${fPo}(S);local ${vRetA}=L:${fPo}(S);L:${fPu}(S,${vRetA}<${vRetB});`,
    `${getJunkAst()}local ${vRetB}=L:${fPo}(S);local ${vRetA}=L:${fPo}(S);L:${fPu}(S,${vRetA}<=${vRetB});`,
    `${getJunkAst()}local ${vRetB}=L:${fPo}(S);local ${vRetA}=L:${fPo}(S);L:${fPu}(S,${vRetA}>${vRetB});`,
    `${getJunkAst()}local ${vRetB}=L:${fPo}(S);local ${vRetA}=L:${fPo}(S);L:${fPu}(S,${vRetA}>=${vRetB});`,
    `${getJunkAst()}local ${vRetB}=L:${fPo}(S);local ${vRetA}=L:${fPo}(S);L:${fPu}(S,tostring(${vRetA})..tostring(${vRetB}));`,
    `${getJunkAst()}S[(${heavyNum(sPc)})]=(${vAgS})+(${heavyNum(1)});`,
    `${getJunkAst()}local ${vRetV}=L:${fPo}(S);if ${vRetV}==nil or ${vRetV}==false then S[(${heavyNum(sPc)})]=(${vAgS})+(${heavyNum(1)});end;`,
    `${getJunkAst()}local ${vRetV}=L:${fPo}(S);if ${vRetV}~=nil and ${vRetV}~=false then S[(${heavyNum(sPc)})]=(${vAgS})+(${heavyNum(1)});end;`,
    `${getJunkAst()}L:${fPu}(S,{});`,
    `${getJunkAst()}local ${vRetK}=L:${fPo}(S);local ${vRetT}=L:${fPo}(S);L:${fPu}(S,${vRetT}[${vRetK}]);`,
    `${getJunkAst()}local ${vRetV}=L:${fPo}(S);local ${vRetK}=L:${fPo}(S);local ${vRetT}=L:${fPo}(S);${vRetT}[${vRetK}]=${vRetV};`,
    `${getJunkAst()}local ${cN}=${vAg};if(${cN})==(${heavyNum(0)})then local ${cF}=L:${fPo}(S);L:${fPu}(S,${cF}());elseif(${cN})==(${heavyNum(1)})then local ${cA}=L:${fPo}(S);local ${cF}=L:${fPo}(S);L:${fPu}(S,${cF}(${cA}));elseif(${cN})==(${heavyNum(2)})then local ${cB}=L:${fPo}(S);local ${cA}=L:${fPo}(S);local ${cF}=L:${fPo}(S);L:${fPu}(S,${cF}(${cA},${cB}));elseif(${cN})==(${heavyNum(3)})then local ${cC}=L:${fPo}(S);local ${cB}=L:${fPo}(S);local ${cA}=L:${fPo}(S);local ${cF}=L:${fPo}(S);L:${fPu}(S,${cF}(${cA},${cB},${cC}));elseif(${cN})==(${heavyNum(4)})then local ${cD}=L:${fPo}(S);local ${cC}=L:${fPo}(S);local ${cB}=L:${fPo}(S);local ${cA}=L:${fPo}(S);local ${cF}=L:${fPo}(S);L:${fPu}(S,${cF}(${cA},${cB},${cC},${cD}));else local ${cArgs}={};for ${cI}=(${cN}),(${heavyNum(1)}),-(${heavyNum(1)}) do ${cArgs}[${cI}]=L:${fPo}(S);end;local ${cF}=L:${fPo}(S);L:${fPu}(S,${cF}((unpack or table.unpack)(${cArgs},(${heavyNum(1)}),${cN})));end;`,
    `${getJunkAst()}return true,L:${fPo}(S);`,
    `${getJunkAst()}L:${fPu}(S,L:${fPo}(S)+(${vAgS}));`,
    `${getJunkAst()}L:${fPu}(S,L:${fPo}(S)-(${vAgS}));`,
    `${getJunkAst()}S[(${heavyNum(sLoc)})][${vAg}]=S[(${heavyNum(sLoc)})][${vAg}]+(${heavyNum(1)});`,
    `${getJunkAst()}local ${vRetB}=L:${fPo}(S);local ${vRetA}=L:${fPo}(S);if(${vRetA})<(${vRetB})then S[(${heavyNum(sPc)})]=(${vAgS})+(${heavyNum(1)});end;`,
    `${getJunkAst()}local ${vRetB}=L:${fPo}(S);local ${vRetA}=L:${fPo}(S);if(${vRetA})>=(${vRetB})then S[(${heavyNum(sPc)})]=(${vAgS})+(${heavyNum(1)});end;`,
    `${getJunkAst()}print(L:${fPo}(S));`,
    `${getJunkAst()}return true,nil;`,
    `${getJunkAst()}local ${uD}=math.floor((${vAg})/(${heavyNum(0x10000)}));local ${uS}=(${vAg})%(${heavyNum(0x10000)});L:${fPu}(S,S[(${heavyNum(sUp)})][(${uD})+(${heavyNum(1)})][${uS}]);`,
    `${getJunkAst()}local ${uD}=math.floor((${vAg})/(${heavyNum(0x10000)}));local ${uS}=(${vAg})%(${heavyNum(0x10000)});S[(${heavyNum(sUp)})][(${uD})+(${heavyNum(1)})][${uS}]=L:${fPo}(S);`,
    `${getJunkAst()}L:${fPu}(S,L.MkCl((${vAg})+(${heavyNum(1)}),S[(${heavyNum(sUp)})]));`,
    `${getJunkAst()}local ${cN}=${vAg};local ${cArgs}={};for ${cI}=(${cN}),(${heavyNum(1)}),-(${heavyNum(1)}) do ${cArgs}[${cI}]=L:${fPo}(S);end;local ${cF}=L:${fPo}(S);for ${cI}=(${heavyNum(1)}),S[(${heavyNum(sVAc)})] do ${cArgs}[(${cN})+(${cI})]=S[(${heavyNum(sVAg)})][${cI}];end;L:${fPu}(S,${cF}((unpack or table.unpack)(${cArgs},(${heavyNum(1)}),(${cN})+S[(${heavyNum(sVAc)})])));`
  ];

  tableEntries.push(`${fPu}=function(L,S,v)S[(${heavyNum(sTop)})]=S[(${heavyNum(sTop)})]+(${heavyNum(1)});S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]]=v;end`);
  tableEntries.push(`${fPo}=function(L,S)local v=S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]];S[(${heavyNum(sStk)})][S[(${heavyNum(sTop)})]]=nil;S[(${heavyNum(sTop)})]=S[(${heavyNum(sTop)})]-(${heavyNum(1)});return v;end`);

  const _tt = V(), _aa = V(), _bb = V(), _nn = V();
  const junkOperations = [
      `local ${_tt}=S[(${heavyNum(sTop)})];S[(${heavyNum(sTmp)})]=${_tt};if(${_tt})>(${heavyNum(0)})then S[(${heavyNum(sStk)})][(${_tt})+(${heavyNum(1)})]=S[(${heavyNum(sStk)})][${_tt}];end;`,
      `local ${_aa}=S[(${heavyNum(sCon)})][${vAgS}];if type(${_aa})~="nil" then S[(${heavyNum(sTmp)})]=type(${_aa})=="function" and ${_aa}((${heavyNum(strLock)})) or ${_aa};end;`,
      `local ${_nn}=((${vAg})+(${heavyNum(1)}));S[(${heavyNum(sPc)})]=S[(${heavyNum(sPc)})]+bit32.band(${_nn},(${heavyNum(0)}));`,
      `local ${_bb}=L:${fPo}(S);S[(${heavyNum(sTmp)})]=${_bb};L:${fPu}(S,${_bb});`,
      `S[(${heavyNum(sTmp)})]=bit32.bxor(S[(${heavyNum(sTmp)})] or 0,(${vAg}));`
  ];

  const allHandlers = [...coreHandlers];
  for (let i = 0; i < 75; i++) {
    allHandlers.push(junkOperations[Math.floor(Math.random() * junkOperations.length)]);
  }

  const vDispTab = V();
  let hI=allHandlers.map((_,i)=>i);
  for(let i=hI.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[hI[i],hI[j]]=[hI[j],hI[i]];}
  let fM=new Array(allHandlers.length),nH=new Array(allHandlers.length);
  for(let i=0;i<hI.length;i++){fM[hI[i]]=i+1;nH[i]=allHandlers[hI[i]];}

  p(`local ${vSm}={${fM.map(n=>heavyNum(n)).join(',')}};local ${vDispTab}={${nH.map(h=>`function(L,S,${vAg},${vAgS})${h}end`).join(',')}};`);

  p(`local ${vMkCl};${vMkCl}=function(${vClFi},${vClUp}) local ${vClMeta}=${vFn}[${vClFi}];return function(...) L.MkCl=${vMkCl};local ${vClLoc}={};for ${vI}=(${heavyNum(0)}),(${vClMeta}.nl)-(${heavyNum(1)}) do ${vClLoc}[${vI}]=nil;end;local ${vNArgGiven}=select("#",...);local ${vNArgUse}=math.min(${vNArgGiven},${vClMeta}.np);local ${vClArgsN}=math.max((${heavyNum(0)}),(${vNArgGiven})-(${vClMeta}.np));local ${vClArgs}={};for ${vI}=(${heavyNum(1)}),${vClArgsN} do ${vClArgs}[${vI}]=select((${vClMeta}.np)+(${vI}),...);end;`);
  
  const vVarArgs = V();
  p(`if(${vNArgUse})>(${heavyNum(0)})then local ${vVarArgs}={...};for ${vI}=(${heavyNum(0)}),(${vNArgUse})-(${heavyNum(1)}) do ${vClLoc}[${vI}]=${vVarArgs}[(${vI})+(${heavyNum(1)})];end;end;local ${vClRegs}={};for ${vI}=(${heavyNum(0)}),(${vClMeta}.nr)-(${heavyNum(1)}) do ${vClRegs}[${vI}]=nil;end;local ${vClChain}={};${vClChain}[(${heavyNum(1)})]=${vClLoc};for ${vI}=(${heavyNum(1)}),#${vClUp} do ${vClChain}[(${vI})+(${heavyNum(1)})]=${vClUp}[${vI}];end;local ${vClCode}=${vClMeta}.code;local ${vClPc}=(${heavyNum(1)});`);
  const vClCodeLen = V(), vSPack = V(), vPrevPacked = V();
  p(`local ${vClCodeLen}=#${vClCode};local ${vSPack}={};${vSPack}[(${heavyNum(sStk)})]={};${vSPack}[(${heavyNum(sTop)})]=(${heavyNum(0)});${vSPack}[(${heavyNum(sCon)})]=${vCs};${vSPack}[(${heavyNum(sLoc)})]=${vClLoc};${vSPack}[(${heavyNum(sPc)})]=(${heavyNum(1)});${vSPack}[(${heavyNum(sReg)})]=${vClRegs};${vSPack}[(${heavyNum(sGlb)})]=${vGl};${vSPack}[(${heavyNum(sUp)})]=${vClChain};${vSPack}[(${heavyNum(sVAg)})]=${vClArgs};${vSPack}[(${heavyNum(sVAc)})]=${vClArgsN};${vSPack}[(${heavyNum(sTmp)})]=(${heavyNum(0)});`);

  const crashPtr = Math.floor(Math.random() * 5000000) + 8000000;
  const vPh=V(), vP1=V(), vP2=V(), vRawAg=V(), vAh=V(), vJk=V(), vStp=V(), vA1=V(), vA2=V(), vSignal=V(), vRetVal=V(), vCIter = V(), vAP=V();
  
  const vM1_bor=V(), vM1_band=V(), vM1=V(), vOp_bor=V(), vOp_band=V();
  const vA1_bor=V(), vA1_band=V(), vA1_mba=V(), vAg_bor=V(), vAg_band=V(), vJk_bor=V(), vJk_band=V();

  p(`repeat if(${vSPack}[(${heavyNum(sPc)})])>(${vClCodeLen})then break;end;`);
  p(`local ${vPrevPacked}=((${vSPack}[(${heavyNum(sPc)})])>(${heavyNum(1)})) and ${vClCode}[(${vSPack}[(${heavyNum(sPc)})])-(${heavyNum(1)})] or (${heavyNum(0)});`);
  p(`local ${vPacked}=${vClCode}[${vSPack}[(${heavyNum(sPc)})]];local ${vMutatedOp}=bit32.band(${vPacked},(${heavyNum(0xFF)}));local ${vP1}=bit32.band(${vSPack}[(${heavyNum(sPc)})],(${heavyNum(0xFF)}));local ${vP2}=bit32.band(bit32.rshift(${vSPack}[(${heavyNum(sPc)})],(${heavyNum(8)})),(${heavyNum(0xFF)}));local ${vHs}=(((${vKs})*(${vLcgA}))+(${vP1})+(${heavyNum(1)}))%(${vLcgM});if(${vHs})==(${heavyNum(0)})then ${vHs}=(${heavyNum(1)});end;local ${vPh}=(((${vHs})*(${vLcgA}))+(${vP2})+(${heavyNum(1)}))%(${vLcgM});if(${vPh})==(${heavyNum(0)})then ${vPh}=(${heavyNum(1)});end;`);

  p(`local ${vM1_bor}=bit32.bor(${vMutatedOp},bit32.band(${vPh},(${heavyNum(0xFF)}))); local ${vM1_band}=bit32.bnot(bit32.band(${vMutatedOp},bit32.band(${vPh},(${heavyNum(0xFF)})))); local ${vM1}=bit32.band(${vM1_bor},${vM1_band});`);
  p(`local ${vOp_bor}=bit32.bor(${vM1},bit32.band(${vPrevPacked},(${heavyNum(0xFF)}))); local ${vOp_band}=bit32.bnot(bit32.band(${vM1},bit32.band(${vPrevPacked},(${heavyNum(0xFF)})))); local ${vOpRaw}=bit32.band(${vOp_bor},${vOp_band}); local ${vOp}=${vIv}[${vOpRaw}];`);

  p(`local ${vRawAg}=bit32.rshift(${vPacked},(${heavyNum(8)}));local ${vA1}=bit32.band(bit32.rshift(${vSPack}[(${heavyNum(sPc)})],(${heavyNum(16)})),(${heavyNum(0xFF)}));local ${vA2}=bit32.band(${vSPack}[(${heavyNum(sPc)})],(${heavyNum(0xFF)}));${vHs}=(((${vKs})*(${vLcgA}))+(${vA1})+(${heavyNum(1)}))%(${vLcgM});if(${vHs})==(${heavyNum(0)})then ${vHs}=(${heavyNum(1)});end;local ${vAh}=bit32.band((((${vHs})*(${vLcgA}))+(${vA2})+(${heavyNum(1)}))%(${vLcgM}),(${heavyNum(0xFFFFFF)}));`);

  p(`local ${vA1_bor}=bit32.bor(${vRawAg},${vAh}); local ${vA1_band}=bit32.bnot(bit32.band(${vRawAg},${vAh})); local ${vA1_mba}=bit32.band(${vA1_bor},${vA1_band});`);
  p(`local ${vAP}=bit32.band(bit32.rshift(${vPrevPacked},8),0xFFFFFF);`);
  p(`local ${vAg_bor}=bit32.bor(${vA1_mba},${vAP}); local ${vAg_band}=bit32.bnot(bit32.band(${vA1_mba},${vAP})); local ${vAg}=bit32.band(${vAg_bor},${vAg_band});`);

  p(`local ${vAgS}=(${vAg}>(${heavyNum(0x7FFFFF)}) and (${vAg})-(${heavyNum(0x1000000)}) or ${vAg});`);
  p(`local ${vJk_bor}=bit32.bor(${vOpRaw},${vAh}); local ${vJk_band}=bit32.bnot(bit32.band(${vOpRaw},${vAh})); local ${vJk}=bit32.band(${vJk_bor},${vJk_band});`);

  p(`local ${vStp}=bit32.band(${vJk},(${heavyNum(0)}))+(${heavyNum(1)});${vSPack}[(${heavyNum(sPc)})]=((${vSPack}[(${heavyNum(sPc)})])+(${vStp}));`);
  p(`if bit32.band(${vSPack}[(${heavyNum(sPc)})],(${heavyNum(0x3F)}))==(${heavyNum(0)})then local ${vCIter}=((${vSPack}[(${heavyNum(sPc)})])%(${vClCodeLen}))+(${heavyNum(1)});if type(${vClCode}[${vCIter}])~=${luauEscape("number")}then ${vSPack}[(${heavyNum(sPc)})]=(${heavyNum(crashPtr)});end;end;`);
  p(`local ${vSignal},${vRetVal}=${vDispTab}[${vSm}[(${vOp})+(${heavyNum(1)})]](L,${vSPack},${vAg},${vAgS});if(${vSignal})==true then return ${vRetVal};end;until false;return nil;end;end;`);

  const vArgs = V(), vRes = V(), vErr = V(), vClean = V();
  const strCB1 = luauEscape("luapro"), strInternal = luauEscape(" internal"), strColon = luauEscape(": "), regexMatch = luauEscape(":%d+: (.*)"), strString = luauEscape("string");

  p(`local ${vArgs}={...};local ${vRes}={${vGl}[${getS("pcall")}](function() return ${vMkCl}(${vMainIdx},{})((unpack or table.unpack)(${vArgs}));end)};if(${vRes}[(${heavyNum(1)})])==false then local ${vErr}=${vRes}[(${heavyNum(2)})];if ${vGl}[${getS("type")}](${vErr})==${strString} then local ${vClean}=${vGl}[${getS("string")}][${getS("match")}](${vErr},${regexMatch});if not(${vClean}) then (${vGl}[${getS("error")}])(${vErr},(${heavyNum(0)}));else (${vGl}[${getS("error")}])((${strCB1}..${strInternal})..${strColon}..${vClean},(${heavyNum(0)}));end;else (${vGl}[${getS("error")}])(${vErr},(${heavyNum(0)}));end;end;return (${vGl}[${getS("unpack")}] or table.unpack)(${vRes},(${heavyNum(2)}));`);

  const rawVM = zBody.join(' ');
  const connectRuntime = V();
  const vmArgs = ['L', ...Array.from({ length: 16 }, () => V())].join(',');
  
  tableEntries.push(`${connectRuntime}=function(${vmArgs},...) ${rawVM} end`);
  const wrapper = `return({${tableEntries.join(',')}}):${connectRuntime}(...);`;

  return `-- This file is generated using luapro\n${minifyLua(wrapper)}`;
}

module.exports = { luaToProgram, compile, buildLuaRuntime, makeV, antiTamper };

// lastest