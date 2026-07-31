#!/usr/bin/env python3
"""
render_network.py — render a graph_build.py JSON into ONE self-contained,
interactive, clustered network HTML (Cytoscape.js + fcose, all inlined; no CDN,
CSP-safe).

Encoding (per OSINT link-analysis best practice):
  node size   = betweenness centrality (brokers/pivots are biggest)
  node color  = community (Louvain)          [toggle: color by entity type]
  node shape  = entity type (domain/operator/tracker/favicon/email/wallet/…)
  edge style  = evidence: solid=confirmed, dashed=inferred
  edge color  = link class: operator(red) / kit(purple) / link(grey) / infra(steel)

Interactions: pan/zoom, click-to-focus (neighbours highlight, rest dims),
detail panel, filter by node type / edge class, color-by toggle, layout toggle.

Usage:
  render_network.py graph.json out.html --title "One operator, 8 sites" \
      --subtitle "Clustered by shared artifacts; operator tied by email+Messenger. Passive OSINT, 2026-07."
"""
import argparse
import json
import os
import sys

# the community palette is defined ONCE in theme.py (sibling) and injected below,
# so it never drifts from graph_to_diagram.py's editable-Mermaid output.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from theme import COMMUNITY_CYCLE  # noqa: E402

VENDOR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vendor")
LIB_FILES = ["cytoscape.min.js", "layout-base.js", "cose-base.js", "cytoscape-fcose.js"]

TEMPLATE = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root{--paper:#f4f1ea;--ink:#1f1d1a;--muted:#6f6a61;--line:#d9d3c7;--panel:#fbfaf6;
    --op:#b00020;--kit:#7b4bab;--link:#b9b2a4;--infra:#3b5566;--accent:#e0a400}
  *{box-sizing:border-box}
  html,body{margin:0;height:100%;background:var(--paper);color:var(--ink);
    font-family:ui-sans-serif,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
  #app{display:grid;grid-template-rows:auto 1fr auto;height:100vh}
  header{padding:14px 20px;border-bottom:1px solid var(--line);background:#fff}
  header h1{margin:0;font-size:19px;font-weight:750;letter-spacing:-.01em;text-wrap:balance}
  header p{margin:4px 0 0;font-size:13px;color:var(--muted);max-width:90ch}
  #main{display:grid;grid-template-columns:220px 1fr 300px;min-height:0}
  aside{border-right:1px solid var(--line);background:var(--panel);overflow:auto;padding:14px}
  aside.right{border-right:0;border-left:1px solid var(--line)}
  aside h2{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:16px 0 8px}
  aside h2:first-child{margin-top:0}
  #cy{width:100%;height:100%;background:
    radial-gradient(circle at 30% 20%, #fbfaf6, var(--paper))}
  .row{display:flex;align-items:center;gap:8px;font-size:13px;margin:5px 0;cursor:pointer;user-select:none}
  .row input{cursor:pointer}
  .sw{width:12px;height:12px;border-radius:3px;flex:none;display:inline-block}
  .toolbar{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px}
  button{font:inherit;font-size:12px;border:1px solid var(--line);background:#fff;color:var(--ink);
    border-radius:5px;padding:5px 9px;cursor:pointer}
  button.on{background:var(--ink);color:#fff;border-color:var(--ink)}
  button:hover{border-color:var(--muted)}
  input[type=search]{width:100%;font:inherit;font-size:13px;padding:6px 8px;border:1px solid var(--line);border-radius:5px}
  .legend .row{cursor:default}
  .shape{font-size:14px;width:16px;text-align:center}
  #detail{font-size:13px}
  #detail .empty{color:var(--muted)}
  #detail .k{color:var(--muted);font-size:11px;letter-spacing:.04em;text-transform:uppercase;margin-top:10px}
  #detail .v{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
  #detail .badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:10px;color:#fff;margin:2px 4px 2px 0}
  .nbr{font-size:12px;padding:3px 0;border-bottom:1px solid var(--line);cursor:pointer}
  .nbr:hover{color:var(--op)}
  .stat{display:flex;justify-content:space-between;font-size:12px;padding:2px 0}
  .stat b{font-variant-numeric:tabular-nums}
  .hint{font-size:11px;color:var(--muted);margin-top:6px;line-height:1.5}
  #bottom{border-top:1px solid var(--line);background:#fff;height:238px;display:grid;
    grid-template-columns:42% 58%;min-height:0;transition:height .15s}
  #bottom.collapsed{height:32px}
  #bottom.collapsed #timeline,#bottom.collapsed #tblwrap,#bottom.collapsed #tlempty{display:none}
  #tlpane{border-right:1px solid var(--line);overflow:hidden;padding:8px 14px;display:flex;flex-direction:column}
  #tblpane{overflow:hidden;padding:8px 14px;display:flex;flex-direction:column}
  .paneh{display:flex;justify-content:space-between;align-items:center;margin-bottom:4px}
  .paneh h2{margin:0}
  #timeline{width:100%;flex:1}
  #tblwrap{overflow:auto;flex:1}
  table.ev{border-collapse:collapse;width:100%;font-size:12px}
  table.ev th{position:sticky;top:0;background:var(--panel);text-align:left;padding:4px 6px;
    font-size:10px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
  table.ev td{padding:3px 6px;border-bottom:1px solid var(--line);white-space:nowrap;max-width:180px;overflow:hidden;text-overflow:ellipsis}
  table.ev tr{cursor:pointer}
  table.ev tbody tr:hover{background:#faf7f0}
  table.ev tr.hlrow{background:#fdf3d6}
  .edot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:5px}
  .dashln{font-style:italic;color:var(--muted)}
  .collapse-btn{border:none;background:none;font-size:13px;color:var(--muted);cursor:pointer}
</style></head><body>
<div id="app">
  <header><h1>__TITLE__</h1><p>__SUBTITLE__</p></header>
  <div id="main">
    <aside class="left">
      <h2>Layout</h2>
      <div class="toolbar" id="layouts">
        <button data-l="fcose" class="on">Organic</button>
        <button data-l="concentric">Radial</button>
        <button data-l="breadthfirst">Hierarchy</button>
      </div>
      <h2>Color by</h2>
      <div class="toolbar" id="colorby">
        <button data-c="community" class="on">Cluster</button>
        <button data-c="type">Type</button>
      </div>
      <h2>Edges (evidence)</h2>
      <div id="edgeFilters"></div>
      <h2>Node types</h2>
      <div id="typeFilters"></div>
      <h2>Search</h2>
      <input type="search" id="search" placeholder="domain, id, wallet…">
      <p class="hint">Click a node to focus its network. Click empty space to reset. Drag to pan, scroll to zoom.</p>
    </aside>
    <div id="cy"></div>
    <aside class="right">
      <h2>Details</h2>
      <div id="detail"><div class="empty">Click a node to inspect it — type, cluster, centrality, evidence, and connections.</div></div>
      <h2>Case</h2>
      <div id="stats"></div>
    </aside>
  </div>
  <section id="bottom">
    <div id="tlpane">
      <div class="paneh"><h2>Timeline — first archived capture</h2>
        <button class="collapse-btn" id="tlToggle" title="collapse">▾</button></div>
      <svg id="timeline" preserveAspectRatio="xMinYMin meet"></svg>
      <p class="hint" id="tlempty" style="display:none">No dates — pass <code>--history</code> to graph_build.py to populate the timeline.</p>
    </div>
    <div id="tblpane">
      <div class="paneh"><h2>Evidence ledger — <span id="evn"></span> links</h2>
        <span class="hint" style="margin:0">click a row or node to cross-highlight</span></div>
      <div id="tblwrap"><table class="ev"><thead><tr>
        <th>From</th><th>Link</th><th>To</th><th>Class</th><th>Conf.</th><th>Evidence</th>
      </tr></thead><tbody id="evbody"></tbody></table></div>
    </div>
  </section>
</div>
<script>__LIBS__</script>
<script>
const GRAPH = __GRAPH__;
cytoscape.use(window.cytoscapeFcose);

// community palette (colorblind-safe, muted, ≤8 then grey)
const COMM = __COMM__;
const EDGE = {operator:getComputedStyle(document.documentElement).getPropertyValue('--op').trim(),
              kit:"#7b4bab", link:"#b9b2a4", infra:"#3b5566"};
const commColor = n => n.data('type')==='operator' ? '#5a1a1a'
    : COMM[n.data('community_rank') % COMM.length];
const TYPE_COLORS = {domain:"#3b5566",operator:"#5a1a1a",email:"#b00020",wallet:"#5a6b3b",
  tracker:"#7b4bab",favicon:"#b0790f",verification:"#2f6b6b",social:"#9a5b2f",ip:"#6f6a61",host:"#9aa0a6",
  registrant:"#8c2d2d",registrar:"#4a6b7a",nameserver:"#6b7a4a",theme:"#7a5a2f",template:"#5a4a7a"};

const elements = [
  ...GRAPH.nodes.map(n=>({data:{...n}})),
  ...GRAPH.edges.map((e,i)=>({data:{id:'e'+i, ...e}}))
];

const cy = cytoscape({
  container: document.getElementById('cy'),
  elements,
  wheelSensitivity: 0.25,
  style: [
    {selector:'node', style:{
      'width':'data(size)','height':'data(size)','shape':'data(shape)',
      'background-color': commColor,
      'border-width':2,'border-color':'#fbfaf6',
      // icon glyph rendered with the name = instant type recognition on the canvas
      'label':(ele)=>((ele.data('icon')||'')+'  '+(ele.data('label')||'')).trim(),
      'font-size':10,'color':'#1f1d1a',
      'text-valign':'bottom','text-margin-y':5,'text-max-width':170,
      'text-wrap':'ellipsis','min-zoomed-font-size':7,
      'text-background-color':'#f4f1ea','text-background-opacity':0.85,
      'text-background-shape':'roundrectangle','text-background-padding':3
    }},
    {selector:'node[type="operator"]', style:{'border-width':3,'border-color':'#b00020','font-size':15,'font-weight':'bold','text-margin-y':7}},
    {selector:'node[type="domain"]', style:{'font-size':12,'font-weight':'bold'}},
    // declutter: hide the many artifact-hub labels at overview zoom — they reappear when you zoom into a region
    {selector:'node[type="tracker"],node[type="favicon"],node[type="social"],node[type="verification"],node[type="ip"],node[type="registrar"],node[type="nameserver"],node[type="template"]',
      style:{'font-size':8,'min-zoomed-font-size':14}},
    // most-connected nodes: a soft gold halo + always-on bold label so key brokers stand out
    {selector:'node.hub', style:{'underlay-color':'#e0a400','underlay-opacity':0.38,'underlay-padding':9,
      'font-weight':'bold','font-size':13,'min-zoomed-font-size':0,'z-index':30,'border-color':'#e0a400'}},
    {selector:'edge', style:{
      'width':'mapData(link_class_w, 0, 1, 1.2, 5)',
      'line-color':(e)=>EDGE[e.data('link_class')]||'#b9b2a4',
      'curve-style':'bezier','target-arrow-shape':'none','opacity':0.7,
      // WHY the link exists — hidden until you focus/hover an edge, so it stays clean
      'label':'data(rel)','font-size':8,'color':'#4a453d','text-opacity':0,
      'text-background-color':'#f4f1ea','text-background-opacity':0.92,
      'text-background-padding':2,'text-rotation':'autorotate','min-zoomed-font-size':7
    }},
    {selector:'edge[confidence="inferred"]', style:{'line-style':'dashed'}},
    {selector:'edge.hi', style:{'text-opacity':1,'opacity':1,'width':'mapData(link_class_w, 0, 1, 2, 6)'}},
    {selector:'.dim', style:{'opacity':0.1,'text-opacity':0.12}},
    {selector:'node.hi', style:{'opacity':1,'text-opacity':1}},
    {selector:'node.sel', style:{'border-width':4,'border-color':'#e0a400'}}
  ]
});
cy.edges().forEach(e=>{const w={operator:1,kit:.55,link:.25,infra:.4}[e.data('link_class')]||.3; e.data('link_class_w',w);});
// mark the most-connected nodes (top ~15% by degree, plus every operator/person anchor) as hubs
(function(){
  const degs=cy.nodes().map(n=>n.degree()).sort((a,b)=>a-b);
  const cut=Math.max(5, degs[Math.floor(degs.length*0.85)]||5);
  cy.nodes().forEach(n=>{ if(['operator','person'].includes(n.data('type')) || n.degree()>=cut) n.addClass('hub'); });
})();
// hovering an edge reveals why the link exists
cy.on('mouseover','edge',e=>e.target.style('text-opacity',1));
cy.on('mouseout','edge',e=>{ if(!e.target.hasClass('hi')) e.target.style('text-opacity',''); });

const LAYOUTS = {
  fcose:{name:'fcose',quality:'proof',animate:false,randomize:true,
         nodeRepulsion:55000,
         idealEdgeLength:e=>e.data('link_class')==='operator'?120:175,
         edgeElasticity:0.1,nodeSeparation:180,packComponents:true,
         gravity:0.12,gravityRange:4.5,tile:true,
         nodeDimensionsIncludeLabels:true},
  concentric:{name:'concentric',animate:false,concentric:n=>n.data('betweenness')*100+n.degree(),
              levelWidth:()=>1,minNodeSpacing:55,nodeDimensionsIncludeLabels:true},
  breadthfirst:{name:'breadthfirst',animate:false,directed:false,spacingFactor:1.6,
                nodeDimensionsIncludeLabels:true}
};
let curLayout='fcose';
function runLayout(name){curLayout=name; cy.layout(LAYOUTS[name]).run();}
runLayout('fcose');

// color-by toggle
function applyColor(mode){
  cy.nodes().forEach(n=>{
    n.style('background-color', mode==='type'
      ? (TYPE_COLORS[n.data('type')]||'#6f6a61') : commColor(n));
  });
}

// focus + context
function focus(node){
  const nbh = node.closedNeighborhood();
  cy.elements().addClass('dim').removeClass('hi');
  nbh.removeClass('dim').addClass('hi');
  cy.nodes().removeClass('sel'); node.addClass('sel');
  showDetail(node);
  const id=node.id();
  document.querySelectorAll('#evbody tr').forEach(tr=>
    tr.classList.toggle('hlrow', tr.dataset.s===id||tr.dataset.t===id));
  document.querySelectorAll('#timeline .tlm').forEach(m=>
    m.setAttribute('stroke', m.dataset.id===id?'#e0a400':'none'));
}
function reset(){cy.elements().removeClass('dim hi'); cy.nodes().removeClass('sel');
  document.querySelectorAll('#evbody tr.hlrow').forEach(tr=>tr.classList.remove('hlrow'));
  document.querySelectorAll('#timeline .tlm').forEach(m=>m.setAttribute('stroke','none'));
  document.getElementById('detail').innerHTML='<div class="empty">Click a node to inspect it.</div>';}

cy.on('tap','node',e=>focus(e.target));
cy.on('tap','edge',e=>showEdgeDetail(e.target));
cy.on('tap',e=>{if(e.target===cy) reset();});

function showDetail(n){
  const d=n.data();
  const nbrs=n.neighborhood('node').map(m=>m).sort((a,b)=>b.data('betweenness')-a.data('betweenness'));
  let h=`<div style="font-size:15px;font-weight:700">${d.icon||''} ${escapeHtml(d.label)}</div>`;
  h+=`<span class="badge" style="background:${TYPE_COLORS[d.type]||'#6f6a61'}">${d.type}</span>`;
  h+=`<span class="badge" style="background:${COMM[d.community_rank%COMM.length]}">cluster ${d.community_rank}</span>`;
  if(d.title && d.title!==d.label){h+=`<div class="k">Title</div><div class="v">${escapeHtml(d.title)}</div>`;}
  if(d.subtype){h+=`<div class="k">Subtype</div><div class="v">${escapeHtml(d.subtype)}</div>`;}
  if(d.coin){h+=`<div class="k">Chain</div><div class="v">${escapeHtml(d.coin)}</div>`;}
  h+=`<div class="k">Centrality</div><div class="stat"><span>betweenness (broker)</span><b>${d.betweenness.toFixed(3)}</b></div>`;
  h+=`<div class="stat"><span>degree</span><b>${d.degree}</b></div>`;
  h+=`<div class="k">Connections (${nbrs.length}) — why linked</div>`;
  nbrs.slice(0,22).forEach(m=>{
    const ed=n.edgesWith(m);
    const why = ed.length ? (ed[0].data('evidence')||ed[0].data('rel')||'') : '';
    h+=`<div class="nbr" data-id="${m.id()}">${m.data('icon')||''} ${escapeHtml(m.data('label'))} `
      +`<span style="color:#6f6a61">${m.data('type')}</span>`
      +(why?`<div style="font-size:11px;color:#8c2d2d;margin:2px 0 0 16px;white-space:normal">↳ ${escapeHtml(why)}</div>`:'')
      +`</div>`;
  });
  const dd=document.getElementById('detail'); dd.innerHTML=h;
  dd.querySelectorAll('.nbr').forEach(el=>el.onclick=()=>{const t=cy.getElementById(el.dataset.id); focus(t); cy.animate({center:{eles:t},zoom:1.4},{duration:300});});
}

function showEdgeDetail(ed){
  const s=cy.getElementById(ed.data('source')), t=cy.getElementById(ed.data('target'));
  cy.elements().addClass('dim').removeClass('hi');
  ed.addClass('hi'); s.addClass('hi'); t.addClass('hi');
  cy.nodes().removeClass('sel');
  let h=`<div style="font-size:14px;font-weight:700">${s.data('icon')||''} ${escapeHtml(s.data('label'))}<br>&nbsp;&nbsp;↕&nbsp; ${t.data('icon')||''} ${escapeHtml(t.data('label'))}</div>`;
  h+=`<span class="badge" style="background:${EDGE[ed.data('link_class')]||'#b9b2a4'}">${ed.data('link_class')}</span>`;
  h+=`<span class="badge" style="background:#6f6a61">${ed.data('confidence')}</span>`;
  h+=`<div class="k">Shared — the fingerprint that links them</div>`;
  const shared=ed.data('shared');
  if(shared && typeof shared==='object'){
    Object.entries(shared).forEach(([k,vals])=>{
      h+=`<div class="stat" style="margin-top:6px"><span style="font-weight:600">${escapeHtml(k)}</span><b>${vals.length}</b></div>`;
      (vals||[]).forEach(v=>{h+=`<div class="v" style="margin-left:10px">${escapeHtml(v)}</div>`;});
    });
  } else {
    h+=`<div class="v">${escapeHtml(ed.data('evidence')||ed.data('rel')||'')}</div>`;
  }
  document.getElementById('detail').innerHTML=h;
}
function escapeHtml(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

// filters
function buildFilters(){
  const eclasses=[...new Set(GRAPH.edges.map(e=>e.link_class))];
  const enames={operator:'Same operator',kit:'Same kit / infra fingerprint',link:'Page link',infra:'Shared infra (IP)'};
  const ef=document.getElementById('edgeFilters');
  eclasses.forEach(c=>{ef.innerHTML+=`<label class="row"><input type="checkbox" checked data-ec="${c}"><span class="sw" style="background:${EDGE[c]}"></span>${enames[c]||c}</label>`;});
  const types=[...new Set(GRAPH.nodes.map(n=>n.type))];
  const tf=document.getElementById('typeFilters');
  types.forEach(t=>{const ic=(GRAPH.nodes.find(n=>n.type===t)||{}).icon||'•';
    tf.innerHTML+=`<label class="row"><input type="checkbox" checked data-nt="${t}"><span class="shape">${ic}</span>${t}</label>`;});
  ef.querySelectorAll('input').forEach(i=>i.onchange=applyFilters);
  tf.querySelectorAll('input').forEach(i=>i.onchange=applyFilters);
}
function applyFilters(){
  const ec=new Set([...document.querySelectorAll('[data-ec]:checked')].map(i=>i.dataset.ec));
  const nt=new Set([...document.querySelectorAll('[data-nt]:checked')].map(i=>i.dataset.nt));
  cy.nodes().forEach(n=>n.style('display', nt.has(n.data('type'))?'element':'none'));
  cy.edges().forEach(e=>e.style('display', ec.has(e.data('link_class'))?'element':'none'));
}

// search
document.getElementById('search').oninput=e=>{
  const q=e.target.value.toLowerCase().trim();
  if(!q){cy.nodes().removeClass('sel'); return;}
  cy.nodes().removeClass('sel');
  const hit=cy.nodes().filter(n=>(n.data('label')+' '+n.data('id')).toLowerCase().includes(q));
  hit.addClass('sel');
  if(hit.length){cy.animate({fit:{eles:hit,padding:80}},{duration:300});}
};

// toolbar wiring
document.querySelectorAll('#layouts button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('#layouts button').forEach(x=>x.classList.remove('on'));
  b.classList.add('on'); runLayout(b.dataset.l);});
document.querySelectorAll('#colorby button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('#colorby button').forEach(x=>x.classList.remove('on'));
  b.classList.add('on'); applyColor(b.dataset.c);});

// case stats
const m=GRAPH.meta;
document.getElementById('stats').innerHTML=
  `<div class="stat"><span>nodes</span><b>${m.nodes}</b></div>`+
  `<div class="stat"><span>edges</span><b>${m.edges}</b></div>`+
  `<div class="stat"><span>clusters</span><b>${m.communities}</b></div>`+
  `<div class="stat"><span>components</span><b>${m.components}</b></div>`;

// evidence ledger
function buildTable(){
  const byId=Object.fromEntries(GRAPH.nodes.map(n=>[n.id,n]));
  const body=document.getElementById('evbody');
  document.getElementById('evn').textContent=GRAPH.edges.length;
  const order={operator:0,kit:1,infra:2,link:3};
  [...GRAPH.edges].sort((a,b)=>(order[a.link_class]-order[b.link_class])).forEach(e=>{
    const s=byId[e.source]||{label:e.source,icon:''}, t=byId[e.target]||{label:e.target,icon:''};
    const tr=document.createElement('tr'); tr.dataset.s=e.source; tr.dataset.t=e.target;
    tr.innerHTML=`<td title="${escapeHtml(s.label)}">${s.icon||''} ${escapeHtml(s.label)}</td>`+
      `<td>${e.rel}</td><td title="${escapeHtml(t.label)}">${t.icon||''} ${escapeHtml(t.label)}</td>`+
      `<td><span class="edot" style="background:${EDGE[e.link_class]||'#b9b2a4'}"></span>${e.link_class}</td>`+
      `<td class="${e.confidence==='inferred'?'dashln':''}">${e.confidence}</td>`+
      `<td title="${escapeHtml(e.evidence||'')}">${escapeHtml(e.evidence||'')}</td>`;
    tr.onclick=()=>{const n=cy.getElementById(e.source); focus(n);
      cy.animate({fit:{eles:cy.getElementById(e.source).union(cy.getElementById(e.target)),padding:140}},{duration:300});};
    body.appendChild(tr);
  });
}

// timeline of first-archived dates
function buildTimeline(){
  const tl=GRAPH.timeline||[];
  const svg=document.getElementById('timeline');
  if(!tl.length){document.getElementById('tlempty').style.display='block'; svg.style.display='none'; return;}
  const W=Math.max(svg.getBoundingClientRect().width||600,360), H=170, pad=46;
  svg.setAttribute('viewBox',`0 0 ${W} ${H}`); svg.setAttribute('height',H);
  const t=e=>new Date(e.date).getTime();
  const min=Math.min(...tl.map(t)), max=Math.max(...tl.map(t))||min+1;
  const X=v=>pad+(W-2*pad)*((v-min)/((max-min)||1));
  const axisY=H-26;
  let s=`<line x1="${pad}" y1="${axisY}" x2="${W-pad}" y2="${axisY}" stroke="#d9d3c7"/>`;
  s+=`<text x="${pad}" y="${H-8}" font-size="10" fill="#6f6a61">${tl[0].date}</text>`;
  s+=`<text x="${W-pad}" y="${H-8}" font-size="10" fill="#6f6a61" text-anchor="end">${tl[tl.length-1].date}</text>`;
  tl.forEach((e,i)=>{
    const px=X(t(e)); const ly=axisY-20-(i%4)*22;
    const col=e.operator_linked?'#b00020':'#3b5566';
    const short=e.label.replace(/\.(shop|online|info|com)$/,'');
    s+=`<line x1="${px}" y1="${axisY}" x2="${px}" y2="${ly}" stroke="#e2ddd2"/>`;
    s+=`<circle class="tlm" data-id="${e.id}" cx="${px}" cy="${axisY}" r="5" fill="${col}" stroke="none" stroke-width="3" style="cursor:pointer"/>`;
    s+=`<text x="${px}" y="${ly-3}" font-size="9" fill="#1f1d1a" text-anchor="middle" style="cursor:pointer" data-id="${e.id}">${escapeHtml(short)}</text>`;
  });
  svg.innerHTML=s;
  svg.querySelectorAll('[data-id]').forEach(m=>m.onclick=()=>{
    const n=cy.getElementById(m.dataset.id); focus(n); cy.animate({center:{eles:n},zoom:1.5},{duration:300});});
}

document.getElementById('tlToggle').onclick=()=>{
  const b=document.getElementById('bottom'); b.classList.toggle('collapsed');
  document.getElementById('tlToggle').textContent=b.classList.contains('collapsed')?'▸':'▾';
};

buildFilters();
buildTable();
buildTimeline();
cy.ready(()=>cy.fit(undefined,60));
window.addEventListener('resize',()=>{document.getElementById('timeline').innerHTML='';buildTimeline();});
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Render a graph_build.py JSON to a self-contained interactive HTML.")
    ap.add_argument("graph", help="graph.json from graph_build.py")
    ap.add_argument("out", help="output .html")
    ap.add_argument("--title", default="OSINT link-analysis network")
    ap.add_argument("--subtitle", default="Clustered network. Node size = broker centrality · color = cluster · shape = entity type.")
    args = ap.parse_args()

    graph = json.load(open(args.graph, encoding="utf-8"))
    libs = "\n".join(open(os.path.join(VENDOR, f), encoding="utf-8").read() for f in LIB_FILES)
    html = (TEMPLATE
            .replace("__TITLE__", args.title)
            .replace("__SUBTITLE__", args.subtitle)
            .replace("__LIBS__", libs)
            .replace("__COMM__", json.dumps(COMMUNITY_CYCLE))
            .replace("__GRAPH__", json.dumps(graph, ensure_ascii=False)))
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"wrote {args.out} ({len(html)//1024} KB, self-contained)")


if __name__ == "__main__":
    main()
