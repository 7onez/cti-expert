/* app.js — the debug dashboard UI. Plain DOM, no framework, no build step.
 *
 * Two conventions the rendering depends on:
 *   est()  wraps a number that is an ESTIMATE (derived from file size, or a dollar figure at
 *          list prices). It styles differently from an exact count on purpose — see style.css.
 *   text() is used for every value that came out of a ledger. Case data (domains, tool args,
 *          prompt text) is rendered as TEXT, never interpolated into innerHTML: a captured
 *          page's own markup must not be able to execute inside the tool inspecting it.
 */
'use strict';

const $ = (s) => document.querySelector(s);
const panel = $('#panel');

const state = {
  tab: 'overview', limit: 40, session: null,
  // trace panel: which session is being replayed, what is folded away, and which steps the
  // reader has opened. `open` is a Set of step indices — kept across a re-render so hitting
  // reload does not close everything you just expanded.
  trace: { session: null, show: { context: false, events: false, thinking: true }, q: '',
           open: new Set() },
};

const TABS = [
  ['overview', 'overview'],
  ['trace', 'trace'],
  ['tokens', 'tokens & cache'],
  ['prompts', 'prompt surface'],
  ['tools', 'tool calls'],
  ['cost', 'cost & credits'],
];

// ---------------------------------------------------------------- helpers
const n = (v) => (v == null ? '—' : Number(v).toLocaleString());
const usd = (v) => (v == null ? '—' : '$' + Number(v).toFixed(Number(v) < 1 ? 4 : 2));
const pct = (v) => (v == null ? '—' : Math.round(v * 100) + '%');

function el(tag, cls, txt) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (txt != null) e.textContent = String(txt);
  return e;
}
/** A value that came from a ledger — always inserted as text. */
function text(v) { return document.createTextNode(v == null ? '—' : String(v)); }
/** Mark a number as an estimate rather than an exact count. */
function est(v, fmt) {
  const e = el('span', 'est', (fmt || n)(v));
  e.title = 'estimate — not an exact count';
  return e;
}
function card(k, v, sub, estimate) {
  const c = el('div', 'card');
  c.appendChild(el('div', 'k', k));
  const val = el('div', 'v');
  if (estimate) val.appendChild(est(v, (x) => x));
  else val.textContent = v;
  c.appendChild(val);
  if (sub) c.appendChild(el('div', 'sub', sub));
  return c;
}
function table(cols, rows, opts) {
  const o = opts || {};
  const t = el('table');
  const hr = el('tr');
  cols.forEach((c) => {
    const th = el('th', c.num ? 'num' : null, c.label);
    hr.appendChild(th);
  });
  t.appendChild(el('thead')).appendChild(hr);
  const tb = el('tbody');
  if (!rows.length) {
    const tr = el('tr');
    const td = el('td', 'empty');
    td.colSpan = cols.length;
    td.textContent = o.empty || 'nothing recorded';
    tr.appendChild(td);
    tb.appendChild(tr);
  }
  rows.forEach((r) => {
    const tr = el('tr', o.onClick ? 'click' : null);
    cols.forEach((c) => {
      const td = el('td', [c.num ? 'num' : '', c.clip ? 'clip' : ''].join(' ').trim() || null);
      const v = c.get(r);
      if (v instanceof Node) td.appendChild(v);
      else td.appendChild(text(v));
      if (c.title) td.title = c.title(r);
      tr.appendChild(td);
    });
    if (o.onClick) tr.onclick = () => o.onClick(r);
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  return t;
}
/** input / cache-read / cache-write split as one bar. */
function cacheBar(t) {
  const rd = t.cache_read || 0;
  const wr = (t.cache_write_5m || 0) + (t.cache_write_1h || 0);
  const inp = t.input || 0;
  const tot = rd + wr + inp || 1;
  const b = el('div', 'bar');
  [['rd', rd], ['wr', wr], ['in', inp]].forEach(([k, v]) => {
    const i = el('i', k);
    i.style.width = (100 * v / tot) + '%';
    b.appendChild(i);
  });
  b.title = `cache read ${n(rd)} · cache write ${n(wr)} · fresh input ${n(inp)}`;
  return b;
}
function legend() {
  const w = el('div', 'legend');
  [['rd', 'cache read (cheap — good)'], ['wr', 'cache write (premium)'],
   ['in', 'fresh input']].forEach(([k, label]) => {
    const s = el('b');
    const sw = el('span', 'sw');
    sw.style.background = k === 'rd' ? 'var(--good)' : k === 'wr' ? 'var(--warn)' : 'var(--accent)';
    s.appendChild(sw);
    s.appendChild(text(label));
    w.appendChild(s);
  });
  return w;
}
function note(txt) { return el('p', 'note', txt); }
function h2(txt) { return el('h2', null, txt); }

async function api(view, params) {
  const q = new URLSearchParams(params || {}).toString();
  const r = await fetch('/api/' + view + (q ? '?' + q : ''));
  const body = await r.json();
  if (!r.ok) throw new Error(body.error || ('HTTP ' + r.status));
  return body;
}

function findingList(findings) {
  const wrap = el('div');
  if (!findings.length) {
    wrap.appendChild(el('p', 'empty', 'No findings — nothing tripped a threshold in the '
      + 'scanned window. That is a statement about the scanned sessions, not about all time.'));
    return wrap;
  }
  findings.forEach((f) => {
    const d = el('div', 'finding ' + (f.severity || 'info'));
    const head = el('div');
    head.appendChild(el('span', 't', f.title));
    if (f.where) {
      head.appendChild(text(' '));
      head.appendChild(el('span', 'where', '— ' + f.where));
    }
    d.appendChild(head);
    if (f.detail) d.appendChild(el('div', 'd', f.detail));
    if (f.why) d.appendChild(el('div', 'why', f.why));
    wrap.appendChild(d);
  });
  return wrap;
}

// ---------------------------------------------------------------- panels
async function renderOverview() {
  const o = await api('overview', { limit: state.limit });
  const f = document.createDocumentFragment();
  const cc = o.claude_code;

  f.appendChild(h2('what looks wrong'));
  f.appendChild(findingList(o.findings));

  f.appendChild(h2('claude code — scanned window'));
  const cards = el('div', 'cards');
  cards.appendChild(card('sessions', n(o.scan.sessions_scanned),
    'of ' + n(o.scan.sessions_total) + ' total'));
  cards.appendChild(card('turns', n(cc.turns)));
  cards.appendChild(card('tool calls', n(cc.tool_calls)));
  cards.appendChild(card('billed tokens', n(cc.input_side_tokens + (cc.toks.output || 0)),
    'incl. cache'));
  cards.appendChild(card('cache read', pct(cc.cache_read_share), 'higher is better'));
  cards.appendChild(card('cache write', pct(cc.cache_write_share), 'lower is better'));
  cards.appendChild(card('cost', usd(cc.cost), 'API list prices', true));
  f.appendChild(cards);
  f.appendChild(note(o.scan.note));
  if (!o.pricing_available) {
    f.appendChild(el('p', 'err', 'tools/cost_report.py did not import — every cost reads $0.00.'));
  }

  f.appendChild(h2('harness runs (SDK-reported)'));
  const hc = el('div', 'cards');
  hc.appendChild(card('runs', n(o.harness.runs)));
  hc.appendChild(card('anthropic cost', usd(o.harness.total), 'from run_cost.jsonl'));
  o.harness.by_phase.slice(0, 5).forEach(([ph, v]) => hc.appendChild(card(ph, usd(v))));
  f.appendChild(hc);

  f.appendChild(h2('third-party api credits'));
  const pc = el('div', 'cards');
  pc.appendChild(card('metered calls', n(o.credits.calls)));
  o.credits.by_provider.slice(0, 6).forEach(([p, v]) => pc.appendChild(card(p, n(v), 'credits')));
  f.appendChild(pc);
  f.appendChild(note(o.cost_note));
  return f;
}

async function renderTokens() {
  if (state.session) return renderSession(state.session);
  const idx = await api('sessions', { limit: state.limit });
  const f = document.createDocumentFragment();
  f.appendChild(h2('sessions — newest first'));
  f.appendChild(note(idx.note + '  Click a row for the turn-by-turn breakdown.'));
  f.appendChild(legend());
  f.appendChild(table([
    { label: 'session', get: (s) => s.session.slice(0, 8), title: (s) => s.path },
    { label: 'title', clip: true, get: (s) => s.title },
    { label: 'started', get: (s) => (s.started || '').replace('T', ' ').slice(0, 16) },
    { label: 'turns', num: true, get: (s) => n(s.turns) },
    { label: 'tools', num: true, get: (s) => n(s.tool_calls) },
    { label: 'in/cache split', get: (s) => cacheBar(s.toks) },
    { label: 'cache rd', num: true, get: (s) => pct(s.cache_read_share) },
    { label: 'peak ctx', num: true, get: (s) => n(s.max_context) },
    { label: 'output', num: true, get: (s) => n(s.toks.output) },
    { label: 'cost', num: true, get: (s) => est(s.cost, usd) },
  ], idx.sessions, { onClick: (s) => { state.session = s.session; render(); },
                     empty: 'no transcripts found in ' + idx.dir }));
  return f;
}

async function renderSession(sid) {
  const d = await api('session', { session: sid });
  const f = document.createDocumentFragment();
  const back = el('button', 'back', '← all sessions');
  back.onclick = () => { state.session = null; render(); };
  f.appendChild(back);
  const replay = el('button', 'back', 'replay this session →');
  replay.title = 'open the trace: prompts, tool arguments and raw results, in order';
  replay.onclick = () => {
    state.tab = 'trace';
    state.trace.session = sid;
    state.trace.open = new Set();
    state.session = null;
    render();
  };
  f.appendChild(replay);
  if (d.error) { f.appendChild(el('p', 'err', d.error)); return f; }

  const s = d.summary;
  f.appendChild(h2(s.title || sid));
  const cards = el('div', 'cards');
  cards.appendChild(card('turns', n(s.turns), s.sidechain_turns ? n(s.sidechain_turns) + ' subagent' : ''));
  cards.appendChild(card('cache read', pct(s.cache_read_share)));
  cards.appendChild(card('cache write', pct(s.cache_write_share)));
  cards.appendChild(card('peak context', n(s.max_context), 'one turn'));
  cards.appendChild(card('cost', usd(s.cost), 'list prices', true));
  cards.appendChild(card('models', Object.keys(s.models).join(', ') || '—'));
  if (s.biggest_tool_result) {
    cards.appendChild(card('largest tool result', n(s.biggest_tool_result) + ' ch',
      s.biggest_tool_result_name));
  }
  f.appendChild(cards);

  f.appendChild(h2('turns'));
  f.appendChild(legend());
  f.appendChild(table([
    { label: '#', num: true, get: (t) => t.n },
    { label: 'time', get: (t) => (t.ts || '').slice(11, 19) },
    { label: 'model', get: (t) => t.models.join(',') + (t.sidechain ? ' ·sub' : '') },
    { label: 'effort', get: (t) => t.effort || '—' },
    { label: 'in/cache split', get: (t) => cacheBar(t.toks) },
    { label: 'context', num: true, get: (t) => n(t.context) },
    { label: 'output', num: true, get: (t) => n(t.toks.output) },
    { label: 'stop', get: (t) => t.stop_reason || '—' },
    { label: 'tools called', clip: true, get: (t) => t.tool_calls.join(', ') || '—' },
    { label: 'result ch', num: true,
      get: (t) => n(t.tool_results.reduce((a, r) => a + r.result_chars, 0) || null) },
    { label: 'cost', num: true, get: (t) => est(t.cost, usd) },
  ], d.turns, { empty: 'no billed turns in this transcript' }));
  if (d.truncated) f.appendChild(note('Turn list truncated at the configured cap.'));
  return f;
}

async function renderPrompts() {
  const p = await api('prompts');
  const f = document.createDocumentFragment();
  f.appendChild(h2('per-phase context floor'));
  f.appendChild(note('What each harness phase carries before the task prompt or any tool result. '
    + 'The harness pins whole SKILL.md bodies as system prompts, so a paragraph added to a skill '
    + 'is paid for on every phase of every case from then on. ' + p.note));
  f.appendChild(table([
    { label: 'phase', get: (r) => r.phase },
    { label: 'pinned files', clip: true, get: (r) => r.parts.join(' + ') },
    { label: 'est. tokens', num: true, get: (r) => est(r.est_tokens) },
    { label: 'missing', get: (r) => r.missing.join(', ') || '—' },
  ], p.phases, { empty: 'no phase composition configured' }));

  f.appendChild(h2('always-loaded files, largest first'));
  f.appendChild(table([
    { label: 'path', get: (r) => r.path },
    { label: 'bytes', num: true, get: (r) => n(r.bytes) },
    { label: 'est. tokens', num: true, get: (r) => est(r.est_tokens) },
    { label: 'present', get: (r) => (r.exists ? 'yes' : 'MISSING') },
  ], p.files));

  const td = p.tool_descriptions;
  f.appendChild(h2('tool description surface'));
  const c = el('div', 'cards');
  c.appendChild(card('tools registered', n(td.tools)));
  c.appendChild(card('est. tokens', n(td.est_tokens), 'descriptions only', true));
  f.appendChild(c);
  f.appendChild(note(td.error || 'Every tool description is context paid on every phase that '
    + 'exposes the tool — the cost of the roster itself, before a single call is made.'));
  return f;
}

async function renderTools() {
  const t = await api('tools', { limit: 300 });
  const f = document.createDocumentFragment();
  f.appendChild(h2('gate ledger'));
  if (!t.have_ledger) {
    f.appendChild(el('p', 'err', t.note));
    return f;
  }
  const c = el('div', 'cards');
  c.appendChild(card('calls recorded', n(t.total)));
  Object.entries(t.by_decision).forEach(([k, v]) => c.appendChild(card(k, n(v))));
  Object.entries(t.by_class).forEach(([k, v]) => c.appendChild(card(k, n(v), 'risk class')));
  f.appendChild(c);
  f.appendChild(note('Ledgers: ' + t.ledgers.join(', ')
    + '. An absent ledger is absence of RECORD, never "nothing happened".'));

  if (t.repeated.length) {
    f.appendChild(h2('identical calls repeated'));
    f.appendChild(note('Same tool, same arguments, same case. Almost always a loop — the result '
      + 'did not register, or a denial was retried unchanged. Pure waste, invisible in a cost total.'));
    f.appendChild(table([
      { label: 'tool', get: (r) => r.tool },
      { label: 'case', get: (r) => r.case || '—' },
      { label: 'count', num: true, get: (r) => r.count },
      { label: 'args', clip: true, get: (r) => r.args },
    ], t.repeated));
  }

  f.appendChild(h2('by tool'));
  f.appendChild(table([
    { label: 'tool', get: (r) => r[0] },
    { label: 'calls', num: true, get: (r) => n(r[1]) },
  ], t.by_tool));

  f.appendChild(h2('most recent calls'));
  f.appendChild(table([
    { label: 'when', get: (r) => (r.ts || '').replace('T', ' ').replace('Z', '') },
    { label: 'decision', get: (r) => {
        const p = el('span', 'pill ' + (r.decision === 'DENY' ? 'deny' : 'allow'), r.decision);
        return p; } },
    { label: 'tool', get: (r) => r.tool },
    { label: 'case', get: (r) => r.case || '—' },
    { label: 'phase', get: (r) => r.phase || '—' },
    { label: 'front-end', get: (r) => r.backend || '—' },
    { label: 'classes', get: (r) => (r.classes || []).join(',') || '—' },
    { label: 'args / reason', clip: true,
      get: (r) => r.reason || JSON.stringify(r.args || {}),
      title: (r) => r.reason || JSON.stringify(r.args || {}) },
  ], t.rows));
  return f;
}

async function renderCost() {
  const [runs, cr] = await Promise.all([api('runs'), api('credits')]);
  const f = document.createDocumentFragment();

  f.appendChild(h2('harness anthropic cost — by case'));
  f.appendChild(note(runs.note));
  f.appendChild(table([
    { label: 'case', get: (r) => r[0] },
    { label: 'usd', num: true, get: (r) => usd(r[1]) },
  ], runs.by_case, { empty: 'no run_cost.jsonl found in any case' }));

  f.appendChild(h2('by phase'));
  f.appendChild(table([
    { label: 'phase', get: (r) => r[0] },
    { label: 'usd', num: true, get: (r) => usd(r[1]) },
  ], runs.by_phase, { empty: 'no phase costs recorded' }));

  f.appendChild(h2('third-party credits — by provider'));
  f.appendChild(note(cr.note));
  f.appendChild(table([
    { label: 'provider', get: (r) => r[0] },
    { label: 'credits', num: true, get: (r) => n(r[1]) },
  ], cr.by_provider, { empty: 'no api_usage.jsonl found' }));

  f.appendChild(h2('credits by case'));
  f.appendChild(table([
    { label: 'case', get: (r) => r[0] },
    { label: 'credits', num: true, get: (r) => n(r[1]) },
  ], cr.by_case));

  f.appendChild(h2('credits by day (last 30)'));
  f.appendChild(table([
    { label: 'day', get: (r) => r[0] },
    { label: 'credits', num: true, get: (r) => n(r[1]) },
  ], cr.by_day));
  if (cr.failed_calls) {
    f.appendChild(note(cr.failed_calls + ' metered call(s) recorded as failed — credits may have '
      + 'been spent for no result.'));
  }
  return f;
}

// ---------------------------------------------------------------- trace (the replay)
//
// This panel answers the question the other five do not: when you asked for an analysis, what
// did the agent actually DO — what went in, which tool it reached for, with which arguments,
// what came back, and what it concluded. It is a conversation replay, not a table.
//
// Every blob is bounded for display and every cut says what it dropped and offers to fetch the
// rest (/api/step). A shortened result rendered as if complete reads as a tool that found
// little — the same failure the harness's own context governor is written to avoid.

const SHORT = (nm) => String(nm || '').replace(/^mcp__[^_]+__/, '');

/** A bounded blob: head, the cut marker, tail — plus an optional "show full" fetch. */
function clipBlock(clip, opts) {
  const o = opts || {};
  const wrap = el('div', 'blob');
  const pre = el('pre');
  pre.textContent = clip && clip.text ? clip.text : (o.empty || '(empty)');
  wrap.appendChild(pre);
  if (clip && clip.truncated) {
    const cut = el('div', 'cut');
    cut.appendChild(text('… ' + n(clip.dropped) + ' of ' + n(clip.chars)
      + ' chars omitted from the MIDDLE — a display cut, not the end of the output. '));
    if (o.onExpand) {
      const b = el('button', 'mini', 'show full');
      b.onclick = async () => {
        b.disabled = true; b.textContent = 'reading…';
        try {
          const full = await o.onExpand();
          const p = el('pre');
          p.textContent = full.text || '(empty)';
          wrap.replaceChildren(p);
          if (full.truncated) wrap.appendChild(note('capped at ' + n(full.chars) + ' chars'));
        } catch (e) { b.textContent = 'failed: ' + e.message; b.disabled = false; }
      };
      cut.appendChild(b);
    }
    wrap.appendChild(cut);
    const tail = el('pre');
    tail.textContent = clip.tail || '';
    wrap.appendChild(tail);
  }
  return wrap;
}

/** model · effort · token split · cost for the API call a step belongs to. */
function turnMeta(t) {
  const m = el('div', 'turnmeta');
  m.appendChild(el('span', 'tag', 'turn ' + t.n));
  m.appendChild(el('span', null, t.models.join(', ')));
  if (t.effort) m.appendChild(el('span', null, 'effort ' + t.effort));
  m.appendChild(cacheBar(t.toks));
  m.appendChild(el('span', null, 'ctx ' + n(t.context)));
  m.appendChild(el('span', null, 'out ' + n(t.toks.output)));
  const c = el('span', null, '');
  c.appendChild(est(t.cost, usd));
  m.appendChild(c);
  if (t.stop_reason && t.stop_reason !== 'end_turn' && t.stop_reason !== 'tool_use') {
    m.appendChild(el('span', 'stop', t.stop_reason));
  }
  return m;
}

/** The horizontal ribbon: the whole run at a glance, one chip per step, click to jump. */
function flowRibbon(flow) {
  const wrap = el('div', 'flow');
  flow.forEach((f) => {
    const cls = 'chip ' + f.kind + (f.err ? ' err' : '');
    const c = el('button', cls, f.kind === 'tool' ? SHORT(f.label)
      : f.kind === 'user' ? 'you' : 'reply');
    c.title = '#' + f.i + ' · ' + f.kind + (f.kind === 'tool' ? ' · ' + f.label : '');
    c.onclick = () => {
      const target = document.getElementById('step-' + f.i);
      if (!target) return;
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      target.classList.add('flash');
      setTimeout(() => target.classList.remove('flash'), 1200);
    };
    wrap.appendChild(c);
  });
  return wrap;
}

function toolStep(s, sid) {
  const box = el('div', 'step tool' + (s.sidechain ? ' sub' : ''));
  box.id = 'step-' + s.i;
  const head = el('div', 'head');
  const state_ = s.pending ? 'pending' : s.is_error ? 'err' : 'ok';
  head.appendChild(el('span', 'dot ' + state_));
  head.appendChild(el('span', 'tname', SHORT(s.name)));
  const argline = el('span', 'argline',
    (s.args.text || '').replace(/\s+/g, ' ').replace(/^\{\s*/, '').slice(0, 160));
  head.appendChild(argline);
  const right = el('span', 'right');
  if (s.gate) {
    right.appendChild(el('span', 'pill ' + (s.gate.decision === 'DENY' ? 'deny' : 'allow'),
      'gate ' + s.gate.decision));
  }
  if (s.interrupted) right.appendChild(el('span', 'pill warn', 'interrupted'));
  if (s.sidechain) right.appendChild(el('span', 'pill info', 'subagent'));
  right.appendChild(el('span', 'dim', s.pending ? 'no result recorded'
    : n(s.result_chars) + ' ch'));
  head.appendChild(right);
  box.appendChild(head);

  const body = el('div', 'body');
  const open = state.trace.open.has(s.i);
  body.hidden = !open;
  head.onclick = () => {
    body.hidden = !body.hidden;
    if (body.hidden) state.trace.open.delete(s.i); else state.trace.open.add(s.i);
  };

  body.appendChild(el('h4', null, 'arguments — what it asked for'));
  body.appendChild(clipBlock(s.args, {
    empty: '(no arguments)',
    onExpand: async () => (await api('step', { session: sid, id: s.id })).args,
  }));
  body.appendChild(el('h4', null, 'raw result — what came back'));
  if (s.pending) {
    body.appendChild(note('No result in this transcript. The call was the last thing recorded, '
      + 'or the turn was interrupted — absence of record, not an empty result.'));
  } else {
    body.appendChild(clipBlock(s.result, {
      empty: '(the tool returned nothing)',
      onExpand: async () => (await api('step', { session: sid, id: s.id })).result,
    }));
  }
  if (s.stderr) {
    body.appendChild(el('h4', null, 'stderr'));
    const p = el('pre', 'stderr');
    p.textContent = s.stderr;
    body.appendChild(p);
  }
  (s.extras || []).forEach((x) => {
    body.appendChild(note(x.kind + (x.media_type ? ' · ' + x.media_type : '')
      + (x.bytes ? ' · ' + n(x.bytes) + ' bytes (not inlined)' : '')));
  });
  if (s.gate && s.gate.reason) body.appendChild(note('gate: ' + s.gate.reason));
  box.appendChild(body);
  if (s.turn) box.appendChild(turnMeta(s.turn));
  return box;
}

function chatStep(s) {
  const kind = s.kind;
  const box = el('div', 'step ' + kind + (s.sidechain ? ' sub' : ''));
  box.id = 'step-' + s.i;
  const head = el('div', 'head');
  head.appendChild(el('span', 'who', kind === 'user' ? 'you'
    : kind === 'assistant' ? 'agent' : 'pinned context'));
  if (s.sidechain) head.appendChild(el('span', 'pill info', 'subagent'));
  head.appendChild(el('span', 'dim', (s.ts || '').slice(11, 19)));
  head.appendChild(el('span', 'dim', n(s.text.chars) + ' ch'));
  box.appendChild(head);

  if (kind === 'context') {
    const body = el('div', 'body');
    const open = state.trace.open.has(s.i);
    body.hidden = !open;
    head.onclick = () => {
      body.hidden = !body.hidden;
      if (body.hidden) state.trace.open.delete(s.i); else state.trace.open.add(s.i);
    };
    head.appendChild(el('span', 'dim', '— click to unfold'));
    body.appendChild(clipBlock(s.text, {}));
    box.appendChild(body);
    return box;
  }

  const p = el('pre', 'say');
  p.textContent = s.text.text || '(no text — this turn only called tools)';
  box.appendChild(p);
  if (s.text.truncated) {
    box.appendChild(note(n(s.text.dropped) + ' of ' + n(s.text.chars)
      + ' chars omitted from the middle for display.'));
    const t2 = el('pre', 'say');
    t2.textContent = s.text.tail || '';
    box.appendChild(t2);
  }
  (s.attachments || []).forEach((x) => {
    box.appendChild(note('attached ' + x.kind + (x.media_type ? ' · ' + x.media_type : '')
      + (x.bytes ? ' · ' + n(x.bytes) + ' bytes (described, not inlined)' : '')));
  });
  if (kind === 'assistant' && state.trace.show.thinking) {
    if (s.thinking_redacted) {
      box.appendChild(note('thinking present but ENCRYPTED by the API — the model did think; '
        + 'the text is not in the transcript.'));
    } else if (s.thinking.chars) {
      const d = el('details', 'thought');
      d.appendChild(el('summary', null, 'thinking · ' + n(s.thinking.chars) + ' ch'));
      d.appendChild(clipBlock(s.thinking, {}));
      box.appendChild(d);
    }
  }
  if (s.turn) box.appendChild(turnMeta(s.turn));
  return box;
}

function eventStep(s) {
  const box = el('div', 'step event');
  box.id = 'step-' + s.i;
  box.appendChild(el('span', 'dim', (s.ts || '').slice(11, 19)));
  box.appendChild(el('span', 'lab', s.label));
  const d = (s.detail && s.detail.text ? s.detail.text : '').replace(/\s+/g, ' ').slice(0, 140);
  if (d) box.appendChild(el('span', 'dim', d));
  return box;
}

function traceControls(sessions) {
  const bar = el('div', 'tracebar');
  const sel = el('select', 'sesspick');
  sessions.forEach((s) => {
    const o = el('option', null,
      (s.started || '').replace('T', ' ').slice(0, 16) + '  ·  ' + (s.title || s.session)
      + '  ·  ' + s.turns + ' turns');
    o.value = s.session;
    if (s.session === state.trace.session) o.selected = true;
    sel.appendChild(o);
  });
  sel.onchange = (e) => {
    state.trace.session = e.target.value;
    state.trace.open = new Set();
    render();
  };
  bar.appendChild(el('label', 'lab', 'session'));
  bar.appendChild(sel);

  [['context', 'pinned context'], ['events', 'hooks & events'], ['thinking', 'thinking']]
    .forEach(([k, label]) => {
      const b = el('button', 'toggle' + (state.trace.show[k] ? ' on' : ''), label);
      b.onclick = () => { state.trace.show[k] = !state.trace.show[k]; render(); };
      bar.appendChild(b);
    });

  const q = el('input', 'find');
  q.type = 'search';
  q.placeholder = 'filter steps…';
  q.value = state.trace.q;
  q.oninput = (e) => {
    state.trace.q = e.target.value;
    clearTimeout(q._t);
    q._t = setTimeout(render, 250);
  };
  bar.appendChild(q);

  const all = el('button', 'toggle', 'expand all tools');
  all.onclick = () => {
    document.querySelectorAll('.step.tool .body').forEach((b) => { b.hidden = false; });
  };
  bar.appendChild(all);
  return bar;
}

function matchesQuery(s, q) {
  if (!q) return true;
  const hay = [s.kind, s.name || '', s.label || '',
    s.text ? s.text.text : '', s.args ? s.args.text : '', s.result ? s.result.text : '']
    .join('\n').toLowerCase();
  return hay.includes(q.toLowerCase());
}

async function renderTrace() {
  const idx = await api('sessions', { limit: state.limit });
  const f = document.createDocumentFragment();
  if (!idx.sessions.length) {
    f.appendChild(el('p', 'err', 'No transcripts in ' + idx.dir
      + ' — nothing to replay. Set CLAUDE_PROJECT_DIR if the store lives elsewhere.'));
    return f;
  }
  if (!state.trace.session || !idx.sessions.some((s) => s.session === state.trace.session)) {
    state.trace.session = idx.sessions[0].session;      // newest run = the one you just ran
  }
  const t = await api('trace', { session: state.trace.session });
  if (t.error) { f.appendChild(el('p', 'err', t.error)); return f; }

  f.appendChild(h2(t.summary.title || state.trace.session));
  f.appendChild(traceControls(idx.sessions));

  const cards = el('div', 'cards');
  cards.appendChild(card('turns', n(t.summary.turns),
    t.summary.sidechain_turns ? n(t.summary.sidechain_turns) + ' subagent' : ''));
  cards.appendChild(card('tool calls', n(t.summary.tool_calls),
    t.tools_used.slice(0, 3).map((x) => SHORT(x[0]) + '×' + x[1]).join(' · ')));
  cards.appendChild(card('result bytes read', n(t.total_result_chars), 'into the context'));
  cards.appendChild(card('peak context', n(t.summary.max_context), 'one turn'));
  cards.appendChild(card('cost', usd(t.summary.cost), 'list prices', true));
  cards.appendChild(card('steps', n(t.steps.length), 'of ' + n(t.records) + ' records'));
  f.appendChild(cards);

  f.appendChild(h2('run flow — click a chip to jump'));
  f.appendChild(flowRibbon(t.flow));

  f.appendChild(h2('replay'));
  f.appendChild(note(t.note));
  const stream = el('div', 'stream');
  let shown = 0;
  t.steps.forEach((s) => {
    if (s.kind === 'context' && !state.trace.show.context) return;
    if (s.kind === 'event' && !state.trace.show.events) return;
    if (!matchesQuery(s, state.trace.q)) return;
    shown += 1;
    stream.appendChild(s.kind === 'tool' ? toolStep(s, t.session)
      : s.kind === 'event' ? eventStep(s) : chatStep(s));
  });
  if (!shown) stream.appendChild(el('p', 'empty', 'No step matches the current filters.'));
  f.appendChild(stream);
  if (t.truncated) {
    f.appendChild(note('Step list truncated at trace.max_steps — the replay is PARTIAL. '
      + 'Raise it in harness/references/dashboard.json.'));
  }
  return f;
}

const RENDER = {
  overview: renderOverview, trace: renderTrace, tokens: renderTokens, prompts: renderPrompts,
  tools: renderTools, cost: renderCost,
};

// ---------------------------------------------------------------- shell
async function render() {
  document.querySelectorAll('#tabs button').forEach((b) => {
    b.classList.toggle('on', b.dataset.tab === state.tab);
  });
  panel.replaceChildren(el('p', 'loading', 'reading ledgers…'));
  try {
    const frag = await RENDER[state.tab]();
    panel.replaceChildren(frag);
  } catch (e) {
    panel.replaceChildren(el('p', 'err', 'failed: ' + e.message));
  }
}

TABS.forEach(([id, label]) => {
  const b = el('button', null, label);
  b.dataset.tab = id;
  b.onclick = () => { state.tab = id; state.session = null; render(); };
  $('#tabs').appendChild(b);
});
$('#limit').onchange = (e) => { state.limit = Number(e.target.value); render(); };
$('#reload').onclick = () => render();
render();
