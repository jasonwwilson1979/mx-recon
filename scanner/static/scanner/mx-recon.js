/* ================================================================
   MX-RECON v3.0 — Django API client + renderers
   The forensic engine now runs server-side (Python / dnspython).
   This file only: CSRF wiring, pipeline UI, log replay, rendering.
   ================================================================ */
'use strict';

const $  = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

let scanBusy = false, REPORT = null;

/* One full pass of the .scanline sweep — keep in sync with the CSS animation.
   A server-side scan can return in well under a second, so the sweep is held
   open for at least this long; otherwise it flashes past and looks absent. */
const SCAN_SWEEP_MS = 2600;
const SCAN_BANNER_PREFIX = '──── ENGAGING TARGET';

function getCookie(name){
  const m = document.cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}

/* ---------------- log console ---------------- */
const logbody = $('#logbody');
function log(msg, cls='info', ts){
  const t = ts || new Date().toISOString().slice(11,19);
  const d = document.createElement('div');
  d.className = 'll ' + cls;
  d.innerHTML = `<span class="ts">[${esc(t)}]</span> <span class="m">${msg}</span>`;
  logbody.appendChild(d);
  logbody.scrollTop = logbody.scrollHeight;
}
$('#btnClearLog').onclick = () => { logbody.innerHTML=''; log('log buffer flushed','dns'); };

/* ---------------- clock + session ---------------- */
$('#sessId').textContent = Math.random().toString(16).slice(2,8).toUpperCase();
setInterval(()=>{ $('#clock').textContent = new Date().toISOString().slice(11,19); }, 1000);
$('#clock').textContent = new Date().toISOString().slice(11,19);

/* ---------------- input helpers ---------------- */
const sleep = ms => new Promise(r=>setTimeout(r,ms));
function setPhase(step, state){
  const li = document.querySelector(`[data-step="${step}"]`);
  if(!li) return;
  li.classList.remove('active','done');
  if(state) li.classList.add(state);
}
function resetPipeline(){ $$('#pipeline li').forEach(li=>li.classList.remove('active','done')); }
function normalizeDomain(raw){
  let d = (raw||'').trim().toLowerCase();
  if(d.includes('@')) d = d.split('@').pop();
  d = d.replace(/^[a-z]+:\/\//,'').split('/')[0].split(':')[0].split('?')[0];
  d = d.replace(/^_dmarc\./,'');
  return d;
}

/* history */
function loadHist(){ try{ return JSON.parse(localStorage.getItem('mx_recon.hist')||'[]'); }catch(e){ return []; } }
function saveHist(d){
  let h = loadHist().filter(x=>x!==d); h.unshift(d); h = h.slice(0,4);
  try{ localStorage.setItem('mx_recon.hist', JSON.stringify(h)); }catch(e){}
  renderHist();
}
function renderHist(){
  const w = $('#histWrap');
  w.querySelectorAll('.hchip').forEach(n=>n.remove());
  loadHist().forEach(d=>{
    const b = document.createElement('button');
    b.className='hchip'; b.textContent=d;
    b.onclick=()=>{ $('#inDomain').value=d; startScan(); };
    w.appendChild(b);
  });
}
renderHist();

/* ---------------- scan sweep line ----------------
   Moved from JS, not by a CSS @keyframes animation: "reduce motion" settings,
   extensions and CSS resets that force animation:none!important all silently
   killed the keyframes, which parked the line at the top of the page. The
   position is recomputed from the clock on every frame, so it always travels. */
let sweepRAF = 0, sweepTimer = 0;

function sweepOffset(now, t0, viewport){
  const span = (viewport || 800) + 6;
  const p = ((now - t0) % SCAN_SWEEP_MS) / SCAN_SWEEP_MS;   // 0..1, wraps around
  return -6 + p * span;                                     // just off the top → off the bottom
}

function cancelSweep(){
  if(sweepRAF && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(sweepRAF);
  if(sweepTimer && typeof clearInterval === 'function') clearInterval(sweepTimer);
  sweepRAF = 0; sweepTimer = 0;
}

function startSweep(){
  const line = document.querySelector('.scanline');
  if(!line) return;
  cancelSweep();
  const t0 = performance.now();
  const viewport = (typeof window !== 'undefined' && window.innerHeight) || 800;
  const place = () => { line.style.transform = `translate3d(0,${sweepOffset(performance.now(), t0, viewport).toFixed(1)}px,0)`; };
  place();
  if(typeof requestAnimationFrame === 'function'){
    const step = () => { place(); sweepRAF = requestAnimationFrame(step); };
    sweepRAF = requestAnimationFrame(step);
  }else{
    sweepTimer = setInterval(place, 30);   // fallback when rAF is unavailable
  }
}

function stopSweep(){
  cancelSweep();
  const line = document.querySelector('.scanline');
  if(line) line.style.transform = 'translate3d(0,-6px,0)';
}

/* ---------------- scan ---------------- */
function sessionId(){ return (($('#sessId')||{}).textContent || '—').trim(); }
function buildVersion(){ return ((document.body && document.body.dataset && document.body.dataset.mxReconVersion) || '3.x').trim(); }
function resolverLabel(){
  const sel = $('#inResolver');
  const opt = sel && sel.selectedOptions && sel.selectedOptions[0];
  return (opt && opt.textContent) ? opt.textContent.trim() : 'System default';
}

async function startScan(){
  if(scanBusy) return;
  const domain = normalizeDomain($('#inDomain').value);
  if(!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(domain)){
    log(`invalid target rejected: "${esc(domain||'(empty)')}"`,'fail');
    $('#inDomain').focus(); $('#inDomain').style.borderColor='var(--red)';
    setTimeout(()=>$('#inDomain').style.borderColor='',1200);
    return;
  }
  const selector = $('#inSelector').value.trim().toLowerCase().replace(/\._domainkey\..*$/,'');
  scanBusy = true;
  const tStart = performance.now();
  const btn = $('#btnRun'); btn.disabled = true; btn.classList.add('busy');
  $('#btnRunTxt').textContent = 'SCANNING';
  /* restart the sweep cleanly on every scan */
  document.body.classList.remove('scanning');
  void document.body.offsetWidth;
  document.body.classList.add('scanning');
  startSweep();
  resetPipeline();
  $('#results').classList.add('hide');
  log(`${SCAN_BANNER_PREFIX}: ${esc(domain).toUpperCase()} ────`,'info');
  log(`scan ${esc(sessionId())} · resolver ${esc(resolverLabel())} · engine v${esc(buildVersion())} · 8 modules armed`,'dns');
  $('#rDomain').textContent = domain;
  saveHist(domain);

  try{
    const res = await fetch('/api/scan', {
      method:'POST',
      headers:{'Content-Type':'application/json','X-CSRFToken':csrfToken()},
      body: JSON.stringify({domain, selector, resolver: $('#inResolver').value}),
    });
    const body = await res.json();
    if(!res.ok){ throw new Error(body.error || ('HTTP '+res.status)); }

    /* replay server-side log, driving the pipeline LEDs */
    await replayLogs(body.logs);

    REPORT = body.report;
    renderScore(body.report);
    renderMX(body.report.mx);
    renderSPF(body.report.spf);
    renderDKIM(body.report.dkim, selector);
    renderDMARC(body.report.dmarc);
    renderRelay(body.report.relay);
    renderRep(body.report.blacklists.domain);
    renderRBL(body.report.blacklists);
    renderDNS(body.report.zone, body.report.protocols);
    renderControl(body.report.control);
    renderRecs(body.report.recommendations);
    renderInventory(body.report.inventory);

    $('#rMeta').textContent = `${body.report.ms} ms · resolver ${esc(body.report.resolver)} · ${esc(body.report.finished).slice(0,16).replace('T',' ')} UTC`;
    const rbox = $('#results');
    rbox.classList.remove('hide');
    $$('.rgrid .card').forEach((c,i)=>{ c.classList.remove('show'); c.style.transitionDelay = (i*70)+'ms'; });
    requestAnimationFrame(()=>requestAnimationFrame(()=>$$('.rgrid .card').forEach(c=>c.classList.add('show'))));
    setTimeout(()=>$('#results').scrollIntoView({behavior:'smooth', block:'start'}), 150);
  }catch(err){
    log('scan aborted: ' + esc(err.message||err),'fail');
  }finally{
    scanBusy = false;
    btn.disabled=false; btn.classList.remove('busy'); $('#btnRunTxt').textContent='RUN SCAN';
    /* hold the sweep open for at least one full pass, so a fast scan still shows it */
    const remaining = SCAN_SWEEP_MS - (performance.now() - tStart);
    const endSweep = () => { stopSweep(); document.body.classList.remove('scanning'); };
    if(remaining > 0) setTimeout(endSweep, remaining);
    else endSweep();
  }
}

/* Replay the server-side log, driving the pipeline LEDs. The ENGAGING banner is
   printed the moment the operator clicks, so the server's copy is skipped —
   exactly one banner per scan, at the top of it. */
async function replayLogs(entries){
  let prevPhase = null;
  for(const entry of entries || []){
    if(entry.msg && entry.msg.indexOf(SCAN_BANNER_PREFIX) === 0) continue;
    if(entry.ph){
      $$('#pipeline li.active').forEach(li=>li.classList.remove('active'));
      if(prevPhase) setPhase(prevPhase,'done');
      setPhase(entry.ph,'active');
      prevPhase = entry.ph;
    }
    log(entry.msg, entry.cls, entry.ts);
    await sleep(30);
  }
  if(prevPhase) setPhase(prevPhase,'done');
  $$('#pipeline li').forEach(li=>li.classList.remove('active'));
}

/* ---------------- renderers ---------------- */
const chip = (cls,txt)=>`<span class="chip ${cls}">${txt}</span>`;
const setStatus = (id,cls,txt)=>{ const el=$(id); if(el) el.innerHTML = chip(cls,txt); };
const csrfToken = () =>
  (document.querySelector('input[name="csrfmiddlewaretoken"]')||{}).value || getCookie('csrftoken') || '';

function renderScore(r){
  const b = r.breakdown;
  const rows = [
    ['SPF', b.spf, 25], ['DKIM', b.dkim, 20], ['DMARC', b.dmarc, 30],
    ['MX/DNS', b.mx, 15], ['RBL', b.rbl, 10]
  ];
  const verdictColor = {HARDENED:'var(--teal)',STRONG:'var(--cyan)',MODERATE:'var(--amber)',WEAK:'var(--amber)',CRITICAL:'var(--red)'}[r.verdict] || 'var(--red)';
  $('#cb-score').innerHTML = `
    <div class="gaugewrap">
      <svg class="gauge" viewBox="0 0 180 180"><circle class="g-bg" cx="90" cy="90" r="76"/><circle class="g-val" id="gVal" cx="90" cy="90" r="76"/></svg>
      <div class="g-center"><div class="g-num" id="gNum">0</div><div class="g-lab">POSTURE / 100</div></div>
    </div>
    <div class="verdict">${chip(r.score>=70?'ok':r.score>=40?'warn':'fail','VERDICT: '+r.verdict)} &nbsp;${chip('mut',r.recommendations.length+' DIRECTIVES')}</div>
    ${rows.map(([l,v,m])=>`<div class="bd"><span class="l">${l}</span><span class="t"><i data-w="${Math.round(100*v/m)}" style="background:${v/m>=.8?'var(--teal)':v/m>=.4?'var(--amber)':'var(--red)'}"></i></span><span class="v">${v}/${m}</span></div>`).join('')}`;
  requestAnimationFrame(()=>requestAnimationFrame(()=>{
    const gv = $('#gVal');
    gv.style.stroke = verdictColor;
    gv.style.strokeDashoffset = 477.5 * (1 - r.score/100);
    let n=0; const t=setInterval(()=>{ n+=Math.ceil(r.score/36); if(n>=r.score){n=r.score;clearInterval(t);} $('#gNum').textContent=n; },28);
    $$('#cb-score .bd i').forEach(i=>i.style.width=i.dataset.w+'%');
  }));
  setStatus('#st-score', r.score>=70?'ok':r.score>=40?'warn':'fail', r.score+'/100');
}

function renderMX(mx){
  if(!mx.length){
    $('#cb-mx').innerHTML = `<div class="note fail">No MX records published for this domain.</div>`;
    setStatus('#st-mx','fail','NO MX'); return;
  }
  const rows = mx.map(m=>`
    <tr>
      <td class="num">${esc(m.prio)}</td>
      <td class="host">${esc(m.host)} ${m.cname?chip('fail','CNAME ✕ RFC2181'):''}</td>
      <td>${m.ips.length?m.ips.map(x=>`<span class="ip">${esc(x)}</span>`).join(''):chip('warn','NO A/AAAA')}</td>
      <td>${m.ptr?esc(m.ptr):(m.ips.length?chip('warn','NO PTR'):'<span class="dim">—</span>')}</td>
    </tr>`).join('');
  const bad = mx.filter(m=>m.cname || !m.ips.length).length;
  $('#cb-mx').innerHTML = `<table class="tbl"><thead><tr><th>PRI</th><th>MAIL HOST</th><th>RESOLVED IP</th><th>rDNS (PTR)</th></tr></thead><tbody>${rows}</tbody></table>`;
  setStatus('#st-mx', bad?'warn':'ok', mx.length+' HOST'+(mx.length>1?'S':'')+(bad?' · '+bad+' ISSUE':' · CLEAN'));
}

function spfNodeHTML(n){
  const badge = n.status!=='OK' ? ` <span class="chip warn">${esc(n.status)}</span>` : '';
  return `<div class="spfn" style="padding-left:${n.depth*20}px">${n.depth?'<span class="tp">└─ </span>':''}<span>${esc(n.domain)}</span><span class="dim"> · ${n.lookups} lookup${n.lookups===1?'':'s'}</span>${badge}${(n.children||[]).map(spfNodeHTML).join('')}</div>`;
}

function renderSPF(spf){
  if(!spf.record){
    $('#cb-spf').innerHTML = `<div class="note fail">No SPF record found — the domain publishes no sender authorisation. Anyone can forge mail claiming to be from this domain.</div>`;
    setStatus('#st-spf','fail','MISSING'); return;
  }
  const all = spf.all;
  const allChip = all==='-all'?chip('ok','HARDFAIL −all'):all==='~all'?chip('warn','SOFTFAIL ~all')
                :all==='+all'?chip('fail','OPEN +all'):all==='?all'?chip('fail','NEUTRAL ?all'):chip('fail','NO TERMINATOR');
  const lk = spf.lookups||0;
  const lkpct = Math.min(100, lk/10*100);
  $('#cb-spf').innerHTML = `
    <div class="rawbox"><code>${esc(spf.record)}</code><button class="copybtn" data-copy="${esc(spf.record)}">COPY</button></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
      ${allChip} ${chip('info', (spf.ips||0)+' DIRECT IP RULES')} ${chip(lk>10?'fail':lk>7?'warn':'ok', lk+'/10 DNS LOOKUPS')}
    </div>
    ${lk>10?`<div class="note warn">Lookup budget exceeded — per RFC 7208 §4.6.4, evaluation beyond 10 DNS queries may be abandoned by receivers.</div>`:''}
    <div class="mono" style="font-size:10px;letter-spacing:.18em;color:var(--faint)">INCLUDE TREE — RECURSIVE RESOLUTION</div>
    <div class="lookbar"><i style="width:${lkpct}%;background:${lk>10?'var(--red)':lk>7?'var(--amber)':'var(--teal)'}"></i></div>
    <div class="spf-tree">${spf.tree?spfNodeHTML(spf.tree):''}</div>`;
  setStatus('#st-spf', all==='-all'&&lk<=10?'ok':all==='-all'?'warn':'fail', all?all.toUpperCase():'PARTIAL');
}

function renderDKIM(hits, userSel){
  if(!hits.length){
    $('#cb-dkim').innerHTML = `<div class="note fail">No DKIM keys found ${userSel?`at selector <span class="mono">${esc(userSel)}</span>`:'after probing 18 common selectors'}. Outbound mail cannot be cryptographically authenticated.</div>`;
    setStatus('#st-dkim','fail','NO KEYS'); return;
  }
  $('#cb-dkim').innerHTML = hits.map(k=>`
    <div style="margin-bottom:14px">
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
        <span class="mono" style="color:var(--violet);font-size:12px">${esc(k.selector)}._domainkey</span>
        ${k.revoked?chip('fail','REVOKED — EMPTY p='):chip(k.bits>=2048?'ok':'warn', `${(k.algo||'rsa').toUpperCase()} · ~${k.bits}-BIT`)}
      </div>
      <div class="rawbox"><code>${esc(k.raw.length>160?k.raw.slice(0,160)+'…':k.raw)}</code><button class="copybtn" data-copy="${esc(k.raw)}">COPY</button></div>
    </div>`).join('');
  const best = Math.max(...hits.map(k=>k.bits));
  setStatus('#st-dkim', hits.some(k=>k.revoked)?'warn':best>=2048?'ok':'warn', hits.length+' KEY'+(hits.length>1?'S':'')+' FOUND');
}

function renderDMARC(dmarc){
  const rec = dmarc.record, dm = dmarc.parsed;
  if(!rec){
    $('#cb-dmarc').innerHTML = `<div class="note fail">No DMARC record at <span class="mono">_dmarc</span>. Forged mail from this domain faces no receiver-side policy enforcement whatsoever.</div>`;
    setStatus('#st-dmarc','fail','MISSING'); return;
  }
  const p = ((dm&&dm.p)||'none').toLowerCase();
  const idx = {none:1, quarantine:2, reject:3}[p] ?? 0;
  const labels = ['MISSING','NONE','QUARANTINE','REJECT'];
  $('#cb-dmarc').innerHTML = `
    <div class="rawbox"><code>${esc(rec)}</code><button class="copybtn" data-copy="${esc(rec)}">COPY</button></div>
    <div class="polmeter">${labels.map((l,i)=>`<div class="${i===idx?'on p'+i:''}">${l}</div>`).join('')}</div>
    <div class="kv">
      <span class="k">POLICY p=</span><span class="v">${esc((dm&&dm.p)||'— (defaults to none)')}</span>
      <span class="k">SUBDOMAIN sp=</span><span class="v">${esc((dm&&dm.sp)||'—')}</span>
      <span class="k">COVERAGE pct=</span><span class="v">${esc((dm&&dm.pct)||'100')}</span>
      <span class="k">AGG REG rua=</span><span class="v">${dm&&dm.rua?esc(dm.rua):chip('warn','NONE')}</span>
      <span class="k">FORENSIC ruf=</span><span class="v">${esc((dm&&dm.ruf)||'—')}</span>
      <span class="k">ALIGNMENT</span><span class="v">adkim=${esc((dm&&dm.adkim)||'r')} · aspf=${esc((dm&&dm.aspf)||'r')}</span>
    </div>`;
  setStatus('#st-dmarc', p==='reject'?'ok':p==='quarantine'?'ok':p==='none'?'warn':'fail','p='+p.toUpperCase());
}

/* ---------------------------------------------------------------- RBL helpers
   A zone that refuses our query is inconclusive — never a listing. Spamhaus is
   the usual culprit: it only answers resolvers it can attribute, so public/cloud
   DNS (Google, Cloudflare) and blocked IP ranges get an error code in
   127.255.255.0/24. Surface the fix inline instead of leaving an unexplained
   BLOCKED cell on screen. */
function rblRefusedZones(bl){
  const ip = (bl && bl.ip) || [], dom = (bl && bl.domain) || [];
  return [...new Set([
    ...ip.filter(r=>(r.cells||[]).some(c=>c.status==='blocked'||c.status==='err')).map(r=>r.zone),
    ...dom.filter(r=>r.status==='blocked'||r.status==='err').map(r=>r.zone),
  ])];
}
const isPublicSpamhaus = z => /(^|\.)spamhaus\.org$/i.test(String(z||''));

function rblFixNote(refused){
  if(!refused.length) return '';
  const spamhaus = refused.filter(isPublicSpamhaus);
  if(!spamhaus.length){
    return `<div class="note warn" style="margin-top:12px">${refused.length} zone(s) did not answer —
      <span class="mono">${refused.map(esc).join(', ')}</span>. Inconclusive, <b>not</b> a listing:
      re-run, or query through another resolver.</div>`;
  }
  return `<div class="note warn" style="margin-top:12px">
    Spamhaus refused ${spamhaus.length} query(ies) — <span class="mono">${spamhaus.map(esc).join(', ')}</span>.
    That is an error answer, <b>not</b> a listing: Spamhaus only answers resolvers it can attribute, so public or
    cloud DNS (Google, Cloudflare, most VPS resolvers) is always refused.
    <br>Two ways to get a real answer: <b>1)</b> keep the resolver on <b>System default</b> so the query leaves from
    this host's own IP — if the host itself points at public DNS, add your own recursive resolver with
    <span class="mono">DJANGO_RESOLVERS_EXTRA</span>; or <b>2)</b> register Spamhaus <b>DQS</b> (free tier available)
    and query the <span class="mono">*.dq.spamhaus.net</span> zones via <span class="mono">DJANGO_RBL_EXTRA_IP</span> /
    <span class="mono">DJANGO_RBL_EXTRA_DOMAIN</span>, disabling the public zones with
    <span class="mono">DJANGO_RBL_DISABLED</span>.
    <br><span class="dim">See README → "Spamhaus answers BLOCKED". An inconclusive zone never costs points — it just
    means unverified.</span>
  </div>`;
}

function rblResolverNote(){
  if(typeof REPORT === 'undefined' || !REPORT || !REPORT.resolver_public) return '';
  return `<div class="note warn" style="margin-top:12px">
    Scanned through <b>${esc(REPORT.resolver || REPORT.resolver_id || 'a public resolver')}</b> — a shared public
    resolver. Blacklist operators cannot attribute those queries to you, so Spamhaus may refuse them (BLOCKED) or
    answer a blanket NXDOMAIN that reads as a <b>false CLEAN</b>. Run the <b>T-01 RBL self-test</b> in the
    Diagnostics section to see whether this resolver actually answers, then re-scan on one it marks <b>OK</b>
    (System default, or a resolver you control).
  </div>`;
}

function renderRep(domMatrix){
  const anyListed = domMatrix.some(r=>r.status==='listed');
  $('#cb-rep').innerHTML = `
    <div class="note ${anyListed?'fail':'info'}" style="margin-bottom:12px">Domain-level abuse lists flag hosts referenced in spam runs, phishing URLs and malware campaigns — independent of your own mail content.</div>
    <table class="tbl"><thead><tr><th>LIST</th><th>ZONE</th><th>STATUS</th></tr></thead><tbody>
    ${domMatrix.map(r=>`<tr><td>${r.url?`<a href="${r.url}" target="_blank" rel="noopener" style="text-decoration:none">${esc(r.name)}</a>`:esc(r.name)}${r.custom?chip('info','CUSTOM'):''}</td>
      <td class="dim">${esc(r.zone)}</td>
      <td>${r.status==='listed'?chip('fail','LISTED '+(r.code||'')):r.status==='clean'?chip('ok','CLEAN')
        :r.status==='blocked'?chip('mut','RESOLVER BLOCKED'):chip('mut','UNVERIFIABLE')}</td></tr>`).join('')}
    </tbody></table>
    ${rblResolverNote()}
    ${rblFixNote(rblRefusedZones({domain:domMatrix}))}`;
  setStatus('#st-rep', anyListed?'fail':'ok', anyListed?'LISTED':'CLEAN');
}

function renderRBL(bl){
  const uniqIPs = [...new Set(bl.ip.flatMap(r=>r.cells.map(c=>c.ip)))];
  if(!uniqIPs.length){
    $('#cb-rbl').innerHTML = `<div class="note warn">No resolvable MX IPs to test against IP-based blacklists.</div>`;
    setStatus('#st-rbl','warn','NO TARGETS'); return;
  }
  const head = uniqIPs.map(ip=>`<th>${esc(ip)}</th>`).join('');
  const zen = c => { if(!c) return '';
    if(/^127\.0\.0\.[23]$/.test(c)) return 'SBL'; if(/^127\.0\.0\.[4-7]$/.test(c)) return 'XBL';
    if(/^127\.0\.0\.1[01]$/.test(c)) return 'PBL'; return c; };
  const listed = bl.ip.flatMap(r=>r.cells).filter(c=>c.status==='listed').length
               + bl.domain.filter(r=>r.status==='listed').length;
  const blocked = bl.ip.flatMap(r=>r.cells).filter(c=>c.status==='blocked'||c.status==='err').length
                + bl.domain.filter(r=>r.status==='blocked'||r.status==='err').length;
  $('#cb-rbl').innerHTML = `
    <div style="overflow-x:auto"><table class="tbl">
      <thead><tr><th style="min-width:150px">BLACKLIST ZONE</th>${head}</tr></thead><tbody>
      ${bl.ip.map(r=>`<tr>
        <td>${r.url?`<a href="${r.url}" target="_blank" rel="noopener" style="text-decoration:none">${esc(r.name)}</a>`:esc(r.name)}${r.custom?chip('info','CUSTOM'):''}<br><span class="dim" style="font-size:10px">${esc(r.zone)}</span></td>
        ${r.cells.map(c=>{
          if(c.status==='listed')  return `<td>${chip('fail','LISTED')}<br><span class="dim" style="font-size:10px">${zen(c.code)}</span></td>`;
          if(c.status==='clean')   return `<td>${chip('ok','CLEAN')}</td>`;
          if(c.status==='blocked') return `<td>${chip('mut','BLOCKED')}</td>`;
          return `<td>${chip('mut','ERR')}</td>`;
        }).join('')}</tr>`).join('')}
      </tbody></table></div>
    <div class="dim mono" style="font-size:10.5px;margin-top:12px;line-height:1.8">
    ▸ <span style="color:var(--red)">LISTED</span> — sending IP appears on the zone; delivery to major providers will degrade or fail.<br>
    ▸ <span style="color:var(--faint)">BLOCKED/ERR</span> — the zone refused our resolver (common for Spamhaus from cloud IPs); inconclusive, not a listing.<br>
    ▸ Zen sub-codes: SBL = listed spam source · XBL = hijacked/infected host · PBL = should not send directly.</div>
    ${rblResolverNote()}
    ${rblFixNote(rblRefusedZones(bl))}`;
  setStatus('#st-rbl', listed?'fail':blocked?'warn':'ok', listed?listed+' LISTED':blocked?blocked+' UNVERIFIED':'ALL CLEAN');
}

/* ---------- M-06 · relay / echo-spoof exposure ---------- */
function renderRelay(relay){
  if(!relay) return;
  const findings = relay.findings || [];
  const relays_ = relay.relays || [];
  const verdictChip = {EXPOSED:'fail', ELEVATED:'warn', WATCH:'warn', HARDENED:'ok'}[relay.verdict] || 'mut';
  const sevChip = s => chip(s===0?'fail':s===1?'warn':s===2?'warn':'mut', SEV_TAGS[s] || 'INFO');
  $('#cb-relay').innerHTML = `
    <div class="note ${relay.verdict==='HARDENED'?'ok':relay.verdict==='EXPOSED'?'fail':'warn'}" style="margin-bottom:12px">
      <b>${esc(relay.headline || '')}</b><br>
      Echo spoofing does not break SPF, DKIM or DMARC — it <b>uses</b> them: mail is handed to a relay this
      domain already authorises, and the relay re-sends it with its own SPF authorisation and its own DKIM
      signature, so the recipient sees a perfectly authenticated message. This panel shows how much sending
      authority is delegated, and which gaps let a relay-injected message through.
    </div>
    ${relays_.length ? `<div class="kv"><span class="k">DELEGATED TO</span><span class="v">${relays_.map(r=>`${esc(r.label)} <span class="dim">(${esc(r.kind_label || r.kind)}, via ${esc(r.domain)})</span>`).join('<br>')}</span></div>` : ''}
    <table class="tbl" style="margin-top:10px"><thead><tr><th style="width:96px">SEVERITY</th><th>FINDING</th><th style="width:34%">FIX</th></tr></thead><tbody>
      ${findings.length ? findings.map(f=>`<tr>
        <td>${sevChip(f.sev)}</td>
        <td><b>${esc(f.title)}</b><br><span class="dim" style="font-size:10.5px">${f.detail}</span></td>
        <td style="font-size:11px">${f.fix}</td>
      </tr>`).join('') : `<tr><td colspan="3" class="dim">No relay or policy exposure found in the published records.</td></tr>`}
    </tbody></table>
    ${(relay.actions || []).length ? `<div class="note info" style="margin-top:12px"><b>NEXT ACTIONS //</b>
      <ol style="margin:8px 0 0 20px;padding:0">${relay.actions.map(a=>`<li style="margin-bottom:6px"><b>${esc(a.title)}</b> — ${esc(a.detail)}</li>`).join('')}</ol>
    </div>` : ''}
    ${(relay.guidance || []).map(g=>`<div style="margin-top:14px">
      <div class="mono" style="font-size:10px;letter-spacing:.16em;color:var(--faint);margin-bottom:6px">HOW TO HARDEN · ${esc(String(g.label||'').toUpperCase())} (${esc(g.kind_label||'')})</div>
      <ul style="margin:0 0 0 20px;padding:0;font-size:12px;line-height:1.75">${(g.steps||[]).map(s=>`<li>${esc(s)}</li>`).join('')}</ul>
    </div>`).join('')}
    ${(relay.includes || []).length ? `<div class="dim mono" style="font-size:10px;margin-top:10px;line-height:1.7">
      SPF INCLUDES › ${relay.includes.map(i=>`${esc(i.domain)}${i.provider?` <span style="color:var(--amber)">[${esc(i.provider)}]</span>`:''}`).join(' · ')}<br>
      SPF ALL › ${esc((relay.checked||{}).spf_all || '—')} · DMARC POLICY › ${esc((relay.checked||{}).dmarc_policy || '—')}
    </div>` : ''}`;
  setStatus('#st-relay', verdictChip, relay.verdict);
}

function renderDNS(zone, protocols){
  const row = (k,v)=>`<div class="kv" style="margin:0"><span class="k">${k}</span><span class="v">${v}</span></div>`;
  $('#cb-dns').innerHTML = `
    <div class="mono" style="font-size:10px;letter-spacing:.18em;color:var(--faint);margin-bottom:8px">ZONE RECORDS</div>
    ${row('A',     zone.a.length?zone.a.map(x=>`<span class="ip">${esc(x)}</span>`).join(''):'<span class="dim">—</span>')}
    ${row('AAAA',  zone.aaaa.length?zone.aaaa.map(x=>`<span class="ip">${esc(x)}</span>`).join(''):'<span class="dim">—</span>')}
    ${row('NS',    zone.ns.length?zone.ns.map(esc).join('<br>'):'<span class="dim">—</span>')}
    ${row('SOA',   zone.soa?`<span style="font-size:11px">${esc(zone.soa.split(' ').slice(0,2).join(' '))}</span>`:'<span class="dim">—</span>')}
    ${row('CNAME', zone.cname?esc(zone.cname):'<span class="dim">none (apex)</span>')}
    ${row('WWW',   zone.wwwCname?esc(zone.wwwCname):'<span class="dim">no CNAME</span>')}
    <div class="mono" style="font-size:10px;letter-spacing:.18em;color:var(--faint);margin:18px 0 8px">TRANSPORT PROTOCOLS</div>
    ${row('MTA-STS', protocols.mtasts?chip('ok','v=STSv1 PUBLISHED'):chip('mut','ABSENT'))}
    ${row('TLS-RPT', protocols.tlsrpt?chip('ok','REPORTING ACTIVE'):chip('mut','ABSENT'))}
    ${row('BIMI',    protocols.bimi?chip('ok','v=BIMI1'):chip('mut','ABSENT'))}`;
  const extras = [protocols.mtasts,protocols.tlsrpt,protocols.bimi].filter(Boolean).length;
  setStatus('#st-dns', extras===3?'ok':'info', extras+'/3 PROTOCOLS');
}

function renderRecs(recs){
  const tags = ['CRITICAL','HIGH','MEDIUM','ENHANCE'];
  $('#cb-rec').innerHTML = recs.length
    ? recs.map(r=>`<div class="rec r${r.sev}"><span class="tag">${tags[r.sev]} · ${esc(r.tag)}</span><div>${r.html}</div></div>`).join('')
    : `<div class="note ok"><b>Fully hardened.</b> No remediation directives generated — SPF hardfail, strong DKIM, enforcing DMARC and clean reputation are all in place. Maintain monitoring and rotate keys on schedule.</div>`;
  setStatus('#st-rec', recs.some(r=>r.sev===0)?'fail':recs.length?'warn':'ok', recs.length+' OPEN');
}

/* ---------- M-10 · full record inventory ---------- */
const INV_ORDER = {MX:0, A:1, AAAA:2, CNAME:3, TXT:4, NS:5, PTR:6, SOA:7};
let invState = {type:'ALL', q:''};

function renderInventory(recs){
  const box = $('#cb-inv');
  if(!recs.length){
    box.innerHTML = `<div class="note warn">No records captured during this run.</div>`;
    setStatus('#st-inv','warn','0 RECORDS'); return;
  }
  const sorted = [...recs].sort((a,b)=>
    (INV_ORDER[a.type] ?? 9) - (INV_ORDER[b.type] ?? 9) || a.name.localeCompare(b.name) || String(a.value).localeCompare(String(b.value)));
  const counts = {};
  sorted.forEach(r=>counts[r.type]=(counts[r.type]||0)+1);
  const types = Object.keys(counts).sort((a,b)=>(INV_ORDER[a]??9)-(INV_ORDER[b]??9));
  const rblCount = sorted.filter(r=>r.source==='rbl').length;

  box.innerHTML = `
    <div class="inv-tools">
      <button class="fchip on" data-f="ALL">ALL<b>${sorted.length}</b></button>
      ${types.map(t=>`<button class="fchip" data-f="${t}">${t}<b>${counts[t]}</b></button>`).join('')}
      <input type="text" id="invSearch" placeholder="filter by name or value…" autocomplete="off" spellcheck="false">
    </div>
    <div class="inv-count" id="invCount"></div>
    <div class="inv-scroll">
      <table class="tbl" id="invTable">
        <thead><tr><th style="width:90px">TYPE</th><th style="width:32%">NAME</th><th>VALUE</th><th style="width:64px">TTL</th><th style="width:88px">SOURCE</th></tr></thead>
        <tbody>
        ${sorted.map(r=>`<tr data-type="${r.type}" data-hay="${esc((r.name+' '+r.value).toLowerCase())}">
          <td><span class="tchip t-${r.type}">${r.type}</span></td>
          <td class="host">${esc(r.name)}</td>
          <td class="inv-val">${esc(r.value)}</td>
          <td class="dim">${r.ttl ?? '—'}</td>
          <td>${r.source==='rbl'?'<span class="src-tag rbl">RBL PROBE</span>':'<span class="src-tag zone">ZONE</span>'}</td>
        </tr>`).join('')}
        </tbody>
      </table>
    </div>
    <div class="dim mono" style="font-size:10.5px;margin-top:12px;line-height:1.8">
    ▸ Every answer record observed by the server during this scan — apex + <span class="mono">www</span> + all MX hosts (A / AAAA / CNAME / PTR),
    every TXT (SPF, DKIM, DMARC, verification strings), NS, SOA, and SPF include-chain TXT records.<br>
    ▸ <span class="src-tag rbl">RBL PROBE</span> rows are synthetic blacklist queries (reversed IP / domain + list zone), included for full transparency —
    ${rblCount} probe response(s) captured this run.</div>`;

  setStatus('#st-inv','info', sorted.length+' RECORDS');
  applyInvFilter();
}
function applyInvFilter(){
  const rows = $$('#invTable tbody tr');
  const {type, q} = invState;
  let shown = 0;
  rows.forEach(tr=>{
    const okT = type==='ALL' || tr.dataset.type===type;
    const okQ = !q || tr.dataset.hay.includes(q);
    const vis = okT && okQ;
    tr.style.display = vis ? '' : 'none';
    if(vis) shown++;
  });
  const c = $('#invCount');
  if(c) c.textContent = `SHOWING ${shown} OF ${rows.length} CAPTURED RECORDS${type!=='ALL'?' · TYPE '+type:''}${q?` · MATCH "${q.toUpperCase()}"`:''}`;
}
document.addEventListener('click', e=>{
  const f = e.target.closest('.fchip');
  if(f && $('#cb-inv').contains(f)){
    $$('#cb-inv .fchip').forEach(x=>x.classList.remove('on'));
    f.classList.add('on');
    invState.type = f.dataset.f;
    applyInvFilter();
  }
});
document.addEventListener('input', e=>{
  if(e.target && e.target.id==='invSearch'){
    invState.q = e.target.value.trim().toLowerCase();
    applyInvFilter();
  }
});

/* ---------- M-10 · domain control (WHOIS/RDAP + NS) ---------- */
function renderControl(c){
  const box = $('#cb-control');
  if(!c){
    box.innerHTML = `<div class="note warn">No domain-control data captured.</div>`;
    setStatus('#st-control','warn','—'); return;
  }
  const who = c.whois || {};
  const dns = c.dnssec || {};
  const ns = c.nameservers || [];
  const row = (k,v)=>`<div class="kv" style="margin:0"><span class="k">${k}</span><span class="v">${v}</span></div>`;
  const date = iso => iso ? esc(String(iso).slice(0,10)) : '<span class="dim">—</span>';
  const events = who.events || {};
  const days = who.days_to_expiry;
  const src = who.error
    ? chip('warn','UNAVAILABLE') + ` <span class="dim" style="font-size:10px">${esc(who.error)}</span>`
    : chip('ok','RDAP') + (who.source ? ` <span class="dim" style="font-size:10px">${esc(String(who.source).replace(/^https?:\/\//,'').split('/')[0])}</span>` : '');
  const statusChips = (who.status || []).map(s=>{
    const low = String(s).toLowerCase();
    const bad = low.includes('hold') || low.includes('delete') || low.includes('redemption');
    return chip(bad ? 'fail' : 'mut', esc(s));
  }).join(' ') || '<span class="dim">—</span>';
  const dnssecChip =
    dns.registry_signed === true && dns.dnskey_published ? chip('ok','SIGNED & VALIDATED')
    : dns.registry_signed === false && dns.dnskey_published ? chip('warn','SIGNED, NO DS PUBLISHED')
    : dns.registry_signed === true && !dns.dnskey_published ? chip('fail','DS BUT NO DNSKEY')
    : dns.dnskey_published ? chip('info','DNSKEY PUBLISHED') : chip('mut','NOT SIGNED');

  box.innerHTML = `
    <div class="mono" style="font-size:10px;letter-spacing:.18em;color:var(--faint);margin-bottom:8px">REGISTRATION — WHO CONTROLS THE DOMAIN</div>
    ${row('REGISTRAR', who.registrar
      ? `${esc(who.registrar)}${who.registrar_id?` <span class="dim">(IANA ${esc(who.registrar_id)})</span>`:''}`
      : '<span class="dim">—</span>')}
    ${row('WHOIS SOURCE', src)}
    ${row('CREATED', date(events.registration))}
    ${row('EXPIRES', date(events.expiration)
      + (days !== null && days !== undefined ? ` <span class="dim">(${days} days)</span>` : ''))}
    ${row('LAST CHANGED', date(events['last changed']))}
    ${row('REGISTRY STATUS', statusChips)}
    <div class="mono" style="font-size:10px;letter-spacing:.18em;color:var(--faint);margin:18px 0 8px">AUTHORITATIVE NAMESERVERS</div>
    ${ns.length ? `<table class="tbl"><thead><tr><th>NAMESERVER</th><th>PROVIDER</th><th>RESOLVED IP</th></tr></thead><tbody>
      ${ns.map(n=>`<tr>
        <td class="host">${esc(n.name)}</td>
        <td>${esc(n.provider)}${n.provider && n.provider !== 'self-hosted / unknown' ? ' ' + chip('info','HOSTED') : ''}</td>
        <td>${n.ips && n.ips.length ? n.ips.map(x=>`<span class="ip">${esc(x)}</span>`).join('') : chip('warn','NO A/AAAA')}</td>
      </tr>`).join('')}
      </tbody></table>` : `<div class="note fail">No NS records published — the domain has no working delegation.</div>`}
    ${c.providers && c.providers.length ? `<div class="dim mono" style="font-size:10px;margin-top:8px">DNS provider(s): ${esc(c.providers.join(', '))}</div>` : ''}
    <div class="mono" style="font-size:10px;letter-spacing:.18em;color:var(--faint);margin:18px 0 8px">ZONE AUTHORITY &amp; DNSSEC</div>
    ${row('SOA PRIMARY', c.soa_primary
      ? `${esc(c.soa_primary)} ${c.soa_primary_in_ns ? chip('ok','IN NS LIST') : chip('warn','NOT IN NS LIST')}`
      : '<span class="dim">—</span>')}
    ${row('DNSSEC', dnssecChip)}
    ${row('DNSKEY RECORDS', dns.dnskey_count !== undefined && dns.dnskey_count !== null ? String(dns.dnskey_count) : '<span class="dim">—</span>')}
    ${who.nameservers && who.nameservers.length
      ? `<div class="dim mono" style="font-size:10px;margin-top:8px">registry delegation: ${esc(who.nameservers.join(', '))}</div>` : ''}`;

  const label = who.error ? 'WHOIS N/A' : (who.registrar ? who.registrar.slice(0, 24) : 'NO REGISTRAR');
  setStatus('#st-control', who.error ? 'warn' : (ns.length ? 'ok' : 'fail'), esc(label));
}

/* ---------------- wiring ---------------- */
$('#btnRun').onclick = startScan;
$('#btnRescan').onclick = startScan;
['inDomain','inSelector'].forEach(id=>$('#'+id).addEventListener('keydown', e=>{ if(e.key==='Enter') startScan(); }));
$$('.schip').forEach(b=>b.onclick=()=>{ $('#inDomain').value=b.dataset.d; startScan(); });
$('#btnExport').onclick = ()=>{
  if(!REPORT) return;
  const blob = new Blob([JSON.stringify(REPORT,null,2)],{type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `mx-recon-${REPORT.target}-${Date.now()}.json`;
  a.click(); URL.revokeObjectURL(a.href);
  log('report dossier exported as JSON (includes full inventory)','ok');
};
document.addEventListener('click', e=>{
  const b = e.target.closest('.copybtn');
  if(!b) return;
  navigator.clipboard?.writeText(b.dataset.copy).then(()=>{
    b.textContent='COPIED'; setTimeout(()=>b.textContent='COPY',1200);
  });
});
document.addEventListener('keydown', e=>{
  if(e.key==='/' && !/INPUT|TEXTAREA/.test(document.activeElement.tagName)){
    e.preventDefault(); $('#inDomain').focus();
  }
});

/* ================================================================
   RESOLVER SELECTOR — pick which DNS resolver performs the lookups
   ================================================================ */
const RESOLVER_KEY = 'mx_recon.resolver';
let RESOLVERS = [];

function lastResolver(){ try{ return localStorage.getItem(RESOLVER_KEY) || ''; }catch(e){ return ''; } }
function rememberResolver(id){ try{ localStorage.setItem(RESOLVER_KEY, id); }catch(e){} }

async function probeResolver(id){
  const dot = $('#resDot'), lbl = $('#resLabel');
  try{
    const res = await fetch('/api/probe?resolver=' + encodeURIComponent(id || ''));
    const j = await res.json();
    if(!res.ok) throw new Error(j.error || ('HTTP '+res.status));
    if(j.ok){
      dot.className = 'dot ok';
      lbl.innerHTML = `RESOLVER: <b>${esc(j.resolver)}</b> · ${j.ms}ms`;
      log(`resolver online — ${esc(j.resolver)} · ${j.ms} ms round-trip`,'ok');
    }else{
      dot.className = 'dot bad'; lbl.textContent = 'RESOLVER: OFFLINE';
      log(`resolver "${esc(id||'system')}" did not answer — check outbound UDP/53 from the server`,'fail');
    }
    return j;
  }catch(e){
    dot.className = 'dot bad'; lbl.textContent = 'RESOLVER: ERROR';
    log('resolver probe failed: ' + esc(e.message||e),'fail');
    return null;
  }
}

async function loadResolvers(){
  const sel = $('#inResolver');
  let defaultId = 'system';
  try{
    const j = await (await fetch('/api/resolvers')).json();
    RESOLVERS = j.resolvers || [];
    defaultId = j.default || 'system';
    const remembered = lastResolver();
    const ids = RESOLVERS.map(r=>r.id);
    const preferred = ids.includes(remembered) ? remembered : (ids.includes(defaultId) ? defaultId : ids[0]);
    sel.innerHTML = RESOLVERS.map(r=>
      `<option value="${esc(r.id)}"${r.id===preferred?' selected':''}>${esc(r.label)}${r.id===remembered?' ★ last used':''}</option>`
    ).join('');
    log(`resolver menu loaded — ${RESOLVERS.length} option(s), using "${esc(preferred)}"`,'dns');
  }catch(e){
    sel.innerHTML = '<option value="system">System default</option>';
    log('resolver menu unavailable — using the system resolver','warn');
  }
  await probeResolver(sel.value || defaultId);
}

function onResolverChange(){
  const id = $('#inResolver').value;
  const chosen = RESOLVERS.find(r=>r.id===id);
  rememberResolver(id);
  $$('#inResolver option').forEach(o=>{ o.textContent = o.textContent.replace(' ★ last used',''); });
  const opt = $$('#inResolver option').find(o=>o.value===id);
  if(opt) opt.textContent += ' ★ last used';
  log(`resolver switched → ${esc(chosen ? chosen.label : id)}`
      + (chosen && chosen.nameservers.length ? ` (${esc(chosen.nameservers.join(', '))})` : ''),'dns');
  if(chosen && chosen.note) log('note: ' + esc(chosen.note),'dns');
  probeResolver(id);
}

/* ================================================================
   RBL RESOLVER SELF-TEST — "is Spamhaus actually answering us?"
   ================================================================ */
const RBL_VERDICT_CHIP = {ok:'ok', partial:'warn', refused:'fail', false_clean:'fail', no_answer:'warn'};

function rblCheckPlaceholder(){
  return `<div class="note info" style="margin-bottom:12px">
    Spamhaus refuses queries from public/open resolvers, and some public resolvers answer a blanket
    NXDOMAIN instead — so everything looks <b>CLEAN</b> while nothing is actually being checked. This runs
    Spamhaus's own <span class="mono">RFC5782</span> test entries through your configured resolvers and shows
    which ones give real answers.</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="gbtn primary" data-rblcheck="all">TEST ALL RESOLVERS</button>
      <button class="gbtn" data-rblcheck="selected">TEST SELECTED ONLY</button>
    </div>
    <div class="dim mono" style="font-size:10.5px;margin-top:12px;line-height:1.8">
      ▸ <span class="mono">test.dbl.spamhaus.org</span> must answer <span class="mono">127.0.1.2</span> — NXDOMAIN means that resolver is being fed "not listed" for everything.<br>
      ▸ <span class="mono">example.com.dbl.spamhaus.org</span> must answer NXDOMAIN (IANA reserved, never listed).<br>
      ▸ <span class="mono">2.0.0.127.zen.spamhaus.org</span> is Spamhaus's ZEN test entry for IP zones.</div>`;
}

async function runRblCheck(scope){
  const box = $('#cb-rblcheck');
  const which = scope === 'all' ? 'every configured resolver' : `resolver "${resolverLabel()}"`;
  box.innerHTML = `<div class="note info">Running Spamhaus test entries against ${esc(which)}…</div>`;
  setStatus('#st-rblcheck','mut','TESTING');
  log(`rbl self-test → ${esc(which)}`,'dns');
  try{
    const q = scope === 'all' ? 'all' : encodeURIComponent($('#inResolver').value);
    const res = await fetch(`/api/rbl-check?resolver=${q}`);
    const body = await res.json();
    if(!res.ok) throw new Error(body.error || ('HTTP '+res.status));
    renderRblCheck(body);
  }catch(err){
    box.innerHTML = `<div class="note fail">Self-test failed: ${esc(err.message||err)}</div>${rblCheckPlaceholder()}`;
    setStatus('#st-rblcheck','fail','ERROR');
    log('rbl self-test aborted: ' + esc(err.message||err),'fail');
  }
}

function renderRblCheck(data){
  if(!data){
    $('#cb-rblcheck').innerHTML = rblCheckPlaceholder();
    setStatus('#st-rblcheck','mut','NOT RUN');
    return;
  }
  const results = data.results || [];
  const s = data.summary || {};
  const row = r => `<tr>
      <td>${esc(r.resolver_id)}${r.resolver_id === data.default ? ' ' + chip('info','DEFAULT') : ''}<br><span class="dim" style="font-size:10px">${esc(r.resolver||'')}</span></td>
      <td>${chip(RBL_VERDICT_CHIP[r.verdict] || 'mut', String(r.verdict||'?').toUpperCase().replace('_',' '))}</td>
      <td>${esc(r.headline||'')}<br><span class="dim" style="font-size:10.5px">${esc(r.detail||'')}</span></td>
      <td>${(r.checks||[]).map(c=>`<div class="mono" style="font-size:10px">${esc(c.query)} → <b>${esc(c.answer||'')}</b> <span class="dim">(want ${esc(c.expected||'')})</span></div>`).join('') || '<span class="dim">—</span>'}</td>
    </tr>`;
  const fix = results.find(r=>r.fix);
  $('#cb-rblcheck').innerHTML = `
    <div class="note ${s.recommended ? 'ok' : 'warn'}" style="margin-bottom:12px">
      <b>${esc(s.headline || 'Self-test complete')}</b>
      ${s.recommended ? `<br>Use <b>${esc(s.recommended)}</b> for blacklist lookups — set <span class="mono">DJANGO_RESOLVER_DEFAULT=${esc(s.recommended)}</span> to make it the default, or pick it in the resolver menu.` : ''}
    </div>
    <table class="tbl"><thead><tr><th>RESOLVER</th><th>VERDICT</th><th>WHAT IT MEANS</th><th>SPAMHAUS TEST ENTRIES</th></tr></thead><tbody>
      ${results.map(row).join('')}
    </tbody></table>
    ${fix ? `<div class="note warn" style="margin-top:12px"><b>FIX //</b> ${esc(fix.fix)}.</div>` : ''}
    <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap">
      <button class="gbtn" data-rblcheck="all">RE-RUN ALL</button>
      <button class="gbtn" data-rblcheck="selected">TEST SELECTED</button>
    </div>`;
  const ok = (s.working || []).length;
  setStatus('#st-rblcheck', ok ? 'ok' : 'fail', `${ok}/${results.length} USABLE`);
  results.forEach(r=>log(
    `rbl self-test · ${esc(r.resolver_id)} → ${String(r.verdict||'?').toUpperCase()} — ${esc(r.headline||'')}`,
    r.verdict === 'ok' ? 'ok' : r.verdict === 'no_answer' ? 'warn' : 'fail'));
}

document.addEventListener('click', ev=>{
  const b = ev.target.closest('[data-rblcheck]');
  if(b){ ev.preventDefault(); runRblCheck(b.dataset.rblcheck === 'all' ? 'all' : 'selected'); }
});


/* ================================================================
   INFO BUTTONS — plain-English explainers for every card
   ================================================================ */
const GLOSSARY = {
  mx: {emoji:'📬', title:'MX', full:'Mail Exchanger', q:'Where should email for this domain be delivered?',
    body:'The MX record is the internet\'s address book entry for incoming mail: it names the servers that accept mail for the domain. Each record has a <b>priority</b> — lower numbers are tried first, higher ones act as backups. Every MX host must resolve to an IP address (A/AAAA) and must not be a CNAME (RFC 2181 §10.3).',
    example:'example.com.  MX  10 mail.example.com.\nexample.com.  MX  20 backup.example.com.',
    note:'No MX at all? Senders fall back to the domain\'s A record and delivery becomes unreliable.'},
  cname: {emoji:'🔗', title:'CNAME', full:'Canonical Name (alias)', q:'Is this name just a pointer to another name?',
    body:'A CNAME says "this name is an alias — go look at that other name instead". Common for <b>www</b> pointing at a host or a CDN. One important rule: an MX target must <b>not</b> be a CNAME, because mail servers need a real IP address.',
    example:'www.example.com.  CNAME  example.com.',
    note:'The transport protocols (MTA-STS, TLS-RPT, BIMI) are also shown on this card — open their explainers below.',
    related:['mtasts','tlsrpt','bimi']},
  spf: {emoji:'🔐', title:'SPF', full:'Sender Policy Framework', q:'Who is allowed to send email for this domain?',
    body:'SPF is a public list of the servers allowed to send mail for the domain. Receivers compare the connecting IP against that list: a match is <b>pass</b>, anything else is a failure. It ends with an <b>all</b> rule — <b>-all</b> = reject everything else (strict), <b>~all</b> = mark it suspicious (soft), <b>?all</b> = no opinion, <b>+all</b> = let anyone send (never do this).',
    example:'v=spf1 include:_spf.google.com ip4:203.0.113.10 -all',
    note:'Each include: costs a DNS lookup, and receivers stop trusting SPF beyond 10 (RFC 7208).'},
  dkim: {emoji:'🔏', title:'DKIM', full:'DomainKeys Identified Mail', q:'Was this email altered in transit, and is it genuinely from the sender?',
    body:'DKIM puts a cryptographic signature on outgoing mail. The receiving server fetches the matching <b>public key</b> from DNS and checks the signature — if the key is missing, or the headers/body changed on the way, the check fails. The key lives at <b>selector._domainkey.domain</b>, which is why the selector matters.',
    example:'google._domainkey.example.com.  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBgkq..."',
    note:'1024-bit keys are considered weak now — use 2048-bit, and keep old selectors published while rotating.'},
  dmarc: {emoji:'👮', title:'DMARC', full:'Domain-based Message Authentication, Reporting & Conformance', q:'What should I do if an email fails SPF and DKIM?',
    body:'DMARC ties SPF and DKIM to the visible <b>From:</b> address and tells receivers what to do on failure: <b>p=none</b> = do nothing (monitor), <b>p=quarantine</b> = send to spam, <b>p=reject</b> = refuse it. It also requests reports (<b>rua=</b>) showing who sends as your domain — including forgers.',
    example:'_dmarc.example.com.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"',
    note:'Without DMARC, spoofed mail from your domain faces no policy at all — it is the highest-value record to publish.'},
  ptr: {emoji:'🔎', title:'PTR', full:'Reverse DNS pointer', q:'Does this IP\'s hostname match, and does it look like a real mail server?',
    body:'PTR is the reverse of an A record: give it an IP and it returns a hostname. Many receivers reject or greylist mail from IPs with no PTR, or where the PTR does not resolve back to the same IP ("forward-confirmed rDNS").',
    example:'21.124.27.52.in-addr.arpa.  PTR  outbound9.example.com.',
    note:'PTR is set by whoever owns the IP (hosting provider or ESP) — not inside your own DNS zone.'},
  rbl: {emoji:'🚫', title:'RBL', full:'Real-time Blackhole List', q:'Is this sending IP or domain on a known spam blocklist?',
    body:'Blacklists publish IPs and domains caught sending spam. Receivers consult them during delivery, and a listing can quietly send your mail to spam or block it outright. Listings are about <b>reputation</b> and are independent of SPF and DKIM.',
    example:'1.2.3.4.zen.spamhaus.org  →  127.0.0.2   (listed as a spam source)',
    note:'Blocked/not-authorised answers (127.0.0.1, 127.255.255.x) are shown as inconclusive, never as listings — a refused query costs you no points. Spamhaus refuses public/cloud resolvers, so pick "System default" in the resolver menu, or use Spamhaus DQS zones (*.dq.spamhaus.net) via DJANGO_RBL_EXTRA_IP / DJANGO_RBL_EXTRA_DOMAIN. See the README for the full recipe.',
    related:['rblcheck']},
  rblcheck: {emoji:'🧪', title:'RBL SELF-TEST', full:'Resolver self-test for blacklist lookups', q:'Is Spamhaus actually answering my resolver?',
    body:'Spamhaus refuses queries from public/open resolvers, and some public resolvers answer a blanket NXDOMAIN ("not listed") instead of an error — so a setup that is being ignored looks perfectly clean. This test queries Spamhaus\'s own RFC5782 test entries, which are documented to return a listing, so "answered clean" can be told apart from "never answered".',
    example:'test.dbl.spamhaus.org → 127.0.1.2 (listed) · example.com.dbl.spamhaus.org → NXDOMAIN (never listed)',
    note:'A resolver that fails here is not a listing problem, it is a resolver problem: switch to one that passes, point DJANGO_RESOLVERS_EXTRA at your own recursive resolver, or move to Spamhaus DQS zones.'},
  mtasts: {emoji:'🔒', title:'MTA-STS', full:'SMTP MTA Strict Transport Security', q:'Must other servers use TLS when delivering mail to this domain?',
    body:'MTA-STS publishes a policy saying "deliver to me only over TLS, and only to these hosts", which blocks silent downgrade attacks. It needs a TXT record plus a small policy file served over HTTPS.',
    example:'_mta-sts.example.com.  TXT  "v=STSv1; id=20260101T000000"',
    note:'Pairs well with TLS-RPT so you learn when a sender cannot use TLS.'},
  tlsrpt: {emoji:'📈', title:'TLS-RPT', full:'SMTP TLS Reporting', q:'Will this domain tell me when TLS delivery fails?',
    body:'TLS-RPT asks other mail servers to send daily reports about TLS failures, so broken or missing encryption becomes visible instead of invisible.',
    example:'_smtp._tls.example.com.  TXT  "v=TLSRPTv1; rua=mailto:tls@example.com"',
    note:'Cheap to add, and it turns "we hope TLS works" into measurable data.'},
  bimi: {emoji:'🏷️', title:'BIMI', full:'Brand Indicators for Message Identification', q:'Can my logo appear next to authenticated mail?',
    body:'BIMI lets a verified brand display a logo in supporting mail clients. It requires an enforcing DMARC policy first, plus a logo served over HTTPS.',
    example:'default._bimi.example.com.  TXT  "v=BIMI1; l=https://example.com/logo.svg"',
    note:'Cosmetic, but it visibly rewards domains that got SPF, DKIM and DMARC right.'},
  relay: {emoji:'📡', title:'RELAY / ECHO-SPOOF', full:'Relay trust and echo-spoofing exposure', q:'Can someone else send mail that authenticates perfectly as this domain?',
    body:'Echo spoofing (the 2024 EchoSpoofing campaign) never breaks SPF, DKIM or DMARC — it uses them. An attacker hands a message to a relay this domain already authorises (an ESP, a security gateway, a hosting platform); the relay <b>echoes</b> it back out with its own SPF authorisation and its own DKIM signature, so it arrives fully authenticated. The precondition is always the same: sending authority delegated to shared infrastructure that does not prove the injecting party owns the domain.',
    example:'SPF: include:pphosted.com ~all · DMARC: p=none → relay trust delegated, no enforcement to fall back on',
    note:'Nothing in DNS can prove a relay verifies domain ownership — so this panel shows how much trust you delegate and which gaps let a relay-injected message through. DMARC rua reports are how you actually notice it happening.'},
  score: {emoji:'📊', title:'POSTURE SCORE', full:'Overall email-security health', q:'How healthy is this domain\'s email setup overall?',
    body:'Five weighted checks add up: SPF (25), DKIM (20), DMARC (30), MX/DNS hygiene (15) and blacklist reputation (10). Treat it as a quick summary and read the remediation directives for the details.',
    example:'SPF 25 + DKIM 20 + DMARC 30 + MX 15 + RBL 10 = 100  →  HARDENED',
    note:'A perfect score is not a guarantee of inbox placement — content and sending history still count.'},
  rep: {emoji:'⚠️', title:'REPUTATION', full:'Domain-level abuse lists', q:'Has this domain itself been flagged for abuse?',
    body:'These lists (Spamhaus DBL, SURBL) flag domains found in spam runs, phishing URLs and malware campaigns — independent of your own mail content.',
    example:'example.com.dbl.spamhaus.org  →  listed  ⇒  links to this domain get filtered',
    note:'URIBL is no longer queried: it answers "query blocked" (127.0.0.1) to unregistered/public resolvers, which used to look like a listing for every domain. If listed, find the cause (compromised site, spamvertised links) before requesting removal.'},
  rec: {emoji:'🛠️', title:'REMEDIATION', full:'What to fix, in priority order', q:'What exactly should I change first?',
    body:'Every finding is ranked CRITICAL → HIGH → MEDIUM → ENHANCE, with the observed evidence and a concrete fix. Start at the top: authentication failures do the most damage to deliverability.',
    example:'CRITICAL · DKIM — publish the key at selector._domainkey.example.com',
    note:'Re-scan after each change so you can watch the score move.'},
  inv: {emoji:'🗃️', title:'INVENTORY', full:'Raw record capture', q:'What did the scan actually observe?',
    body:'Every DNS answer collected during the scan, deduplicated: apex and www records, all MX hosts, every TXT (SPF, DKIM, DMARC, verification strings), NS, SOA, PTR, plus the synthetic blacklist probes.',
    example:'TXT  _dmarc.example.com  "v=DMARC1; p=reject"  TTL 3600  ZONE',
    note:'Useful for audits and change tracking — export the JSON dossier to keep a snapshot.'},
  control: {emoji:'🛂', title:'DOMAIN CONTROL', full:'WHOIS/RDAP · nameservers · DNSSEC', q:'Who actually controls this domain and its DNS records?',
    body:'Two independent sources of truth: the <b>registry/registrar</b> record (WHOIS, fetched here as RDAP over HTTPS) which says who owns the domain and when it expires, and the <b>nameservers</b> that actually serve the zone. Comparing them shows who is really in charge of your mail DNS — and catches delegations that point somewhere else.',
    example:'registrar: GoDaddy · expires 2027-04-01 · NS: ns1.cloudflare.com (Cloudflare), ns2.cloudflare.com',
    note:'If the registry nameservers differ from the live ones, delegation changed and has not propagated — or the domain is managed by another provider.',
    related:['whois','ns']},
  whois: {emoji:'📜', title:'WHOIS / RDAP', full:'Registry registration record', q:'Who owns the domain, and when does it expire?',
    body:'RDAP is the ICANN-mandated successor to port-43 WHOIS: registrar, creation/expiry dates, registry status flags and the delegated nameservers, delivered as JSON over HTTPS. Registrant contact details are usually redacted for privacy.',
    example:'expires 2026-11-01 (in 24 days)  ⇒  renew now — an expired domain stops receiving mail',
    note:'An expiring domain is the one failure mode that no amount of SPF, DKIM or DMARC can survive.'},
  ns: {emoji:'🧭', title:'NS', full:'Nameservers (delegation)', q:'Which servers are authoritative for this zone?',
    body:'NS records at the registry delegate your zone to specific servers — and whoever controls those servers controls every record, including MX, SPF, DKIM and DMARC. MX-RECON resolves each one and attributes the provider, so you can see where the zone really lives.',
    example:'ns1.cloudflare.com (Cloudflare) · ns2.cloudflare.com (Cloudflare)  ⇒  zone managed at Cloudflare',
    note:'The SOA primary should appear in the NS list; if it does not, zone transfers and NOTIFY messages can fail.'},
  diagcauses: {emoji:'🧭', title:'ROOT CAUSES', full:'Why this specific message was filtered', q:'What went wrong with this email?',
    body:'Each finding combines what the receiving gateway recorded (Authentication-Results, spam headers) with what DNS says <b>right now</b>, so you can tell a missing record from a rotated key or a reputation problem.',
    example:'dkim=fail (No key)  +  paubox._domainkey.example.com NXDOMAIN  ⇒  the key was never published',
    note:'DNS changes made after delivery explain most mismatches between the gateway verdict and a live check.'},
  diagauth: {emoji:'🧾', title:'AUTHENTICATION RESULTS', full:'Every hop\'s verdict', q:'What did each server think of this message?',
    body:'Every mail server that handles the message may stamp its own Authentication-Results header with spf/dkim/dmarc/arc outcomes. The gateway closest to the mailbox is the one that decides the folder.',
    example:'mx.example.net; spf=pass smtp.mailfrom=a@b.com; dkim=fail header.d=b.com; dmarc=none',
    note:'Intermediate hops often record only arc=, so look for the header carrying spf/dkim/dmarc.'},
  diagdkim: {emoji:'🔏', title:'DKIM DNS CHECK', full:'Does the signing selector exist?', q:'Can receivers verify the signature this message carries?',
    body:'The message names the selector and domain it was signed with, and we look that selector up live. If no key exists, the signature can never verify — that is a hard failure, not a reputation problem.',
    example:'s=paubox d=example.com  →  paubox._domainkey.example.com NXDOMAIN  ⇒  unverifiable',
    note:'The signature length also hints at the key size, which helps when the DNS record is missing entirely.'},
  diagspf: {emoji:'🔐', title:'SPF EVALUATION', full:'Is the sending IP really authorised?', q:'Does the envelope domain\'s SPF record allow this IP?',
    body:'We re-evaluate the envelope domain\'s SPF record against the IP that actually connected to the receiving gateway, then compare our result with the gateway\'s verdict.',
    example:'drcfamilydentistry.com → include:_spf.paubox.com → ip4:52.27.124.21  ⇒  pass',
    note:'A pass here alongside a DKIM failure means the ESP is authorised — the DKIM key is the missing piece.'},
  diaghops: {emoji:'🛰️', title:'RECEIVED CHAIN', full:'The route the message took', q:'Where did this message actually come from?',
    body:'Received headers are added by each hop, newest first, and record the connecting IP, the protocol and whether TLS was used. Plaintext hops are both a hygiene and a privacy problem.',
    example:'from outbound9.example.com [52.27.124.21] by mx.example.net with ESMTPS (TLSv1.2)',
    note:'The topmost Received shows the IP the destination gateway saw — the one we test against SPF and blacklists.'},
  diagate: {emoji:'🧯', title:'GATEWAY HEADERS', full:'Filter and reputation stamps', q:'What did the spam filter decide, and why?',
    body:'These headers come from the filtering systems: SpamAssassin scores and rules, Microsoft SCL, and vendor codes such as Barracuda\'s X-BESS-REASON. They are the closest thing to the filter explaining itself.',
    example:'X-Spam-Flag: YES · X-Spam-Status: score=6.2 required=5.0 · X-BESS-REASON: dkim',
    note:'Vendor reason codes are surfaced verbatim — the wording is theirs, not ours.'},
  diagdns: {emoji:'📡', title:'DNS CROSS-CHECK LOG', full:'Every lookup performed', q:'What exactly was queried, and what came back?',
    body:'Full transparency: every DNS question the diagnosis asked, the response status (NOERROR / NXDOMAIN / error) and the answer it returned.',
    example:'paubox._domainkey.example.com  TXT  NXDOMAIN  —',
    note:'Paste this log into a support ticket with your ESP — it usually ends the back-and-forth.'},
};

const INFO_TARGETS = [
  ['card-score','score'], ['card-mx','mx'], ['card-spf','spf'], ['card-dkim','dkim'], ['card-dmarc','dmarc'],
  ['card-rep','rep'], ['card-rbl','rbl'], ['card-relay','relay'], ['card-dns','cname'], ['card-control','control'], ['card-rec','rec'], ['card-inv','inv'],
  ['card-diagcauses','diagcauses'], ['card-diagauth','diagauth'], ['card-diagdkim','diagdkim'],
  ['card-diagspf','diagspf'], ['card-diaghops','diaghops'], ['card-diaggate','diagate'], ['card-diagdns','diagdns'],
  ['card-rblcheck','rblcheck'],
];

function attachInfoButtons(){
  INFO_TARGETS.forEach(([cardId, key])=>{
    const card = document.getElementById(cardId);
    if(!card || card.querySelector('.infobtn')) return;
    const header = card.querySelector('.ch');
    if(!header) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'infobtn';
    btn.textContent = 'i';
    btn.title = 'What is this?';
    btn.setAttribute('aria-label', 'Explain ' + ((GLOSSARY[key]||{}).title || key));
    btn.addEventListener('click', ev=>{ ev.preventDefault(); ev.stopPropagation(); showInfo(key); });
    header.appendChild(btn);
  });
}

function showInfo(key){
  const g = GLOSSARY[key];
  if(!g) return;
  $('#infoPopEmoji').textContent = g.emoji || 'ℹ';
  $('#infoPopTitle').textContent = g.title || key;
  $('#infoPopFull').textContent = g.full || '';
  $('#infoPopQ').textContent = g.q || '';
  $('#infoPopBody').innerHTML = g.body || '';
  $('#infoPopExample').textContent = g.example || '';
  const related = (g.related || []).map(r=>
    `<button class="gbtn" data-related="${esc(r)}">${esc((GLOSSARY[r]||{}).title || r)}</button>`).join('');
  $('#infoPopNote').innerHTML = esc(g.note || '') + (related ? `<div class="info-related">${related}</div>` : '');
  $('#infoPop').classList.remove('hide');
  document.body.style.overflow = 'hidden';
}

function hideInfo(){
  const pop = $('#infoPop');
  if(!pop || pop.classList.contains('hide')) return;
  pop.classList.add('hide');
  document.body.style.overflow = '';
}

document.addEventListener('click', ev=>{
  if(ev.target.closest('[data-info-close]')) hideInfo();
  const rel = ev.target.closest('[data-related]');
  if(rel) showInfo(rel.dataset.related);
});
document.addEventListener('keydown', ev=>{
  if(ev.key === 'Escape') hideInfo();
});

/* ================================================================
   COPY SUMMARY — short plain text sized for email / Teams / tickets
   ================================================================ */
const SEV_TAGS = ['CRITICAL','HIGH','MEDIUM','ENHANCE'];

function plain(value){
  return String(value == null ? '' : value)
    .replace(/<[^>]+>/g,'')
    .replace(/\s+([,.!?;:)])/g,'$1')
    .replace(/\s+/g,' ')
    .trim();
}
function clip(value, max){
  const t = plain(value);
  return t.length > max ? t.slice(0, max - 1).trimEnd() + '…' : t;
}
function fmtWhen(iso){
  const s = String(iso || '');
  return s.length >= 16 ? s.slice(0, 16).replace('T',' ') + ' UTC' : (s || '—');
}

function buildScanSummary(r){
  if(!r) return '';
  const b = r.breakdown || {};
  const L = [];
  L.push('MX-RECON — email security summary');
  L.push(`${r.target} · scanned ${fmtWhen(r.finished)} · resolver ${plain(r.resolver)}${r.resolver_public ? ' (public DNS — blacklist rows unverified)' : ''}`);
  L.push(`Score ${r.score}/100 (${r.verdict}) — SPF ${b.spf}/25 · DKIM ${b.dkim}/20 · DMARC ${b.dmarc}/30 · MX ${b.mx}/15 · RBL ${b.rbl}/10`);
  L.push('');
  const recs = r.recommendations || [];
  if(recs.length){
    L.push(`What to fix (${recs.length}):`);
    recs.slice(0,8).forEach((rec,i)=>{
      L.push(`${i+1}. [${SEV_TAGS[rec.sev] || 'INFO'}] ${rec.tag}: ${clip(rec.text || rec.html, 160)}`);
    });
    if(recs.length > 8) L.push(`   … +${recs.length - 8} more (see the full report)`);
  }else{
    L.push('What to fix: nothing — SPF, DKIM, DMARC, MX and reputation all check out.');
  }
  L.push('');
  L.push('Records');
  const mx = r.mx || [];
  L.push('- MX: ' + (mx.length
    ? mx.slice(0,4).map(m=>`${m.host} [${(m.ips||[])[0] || 'no IP'}]`).join(', ') + (mx.length > 4 ? `, +${mx.length-4} more` : '')
    : 'none published'));
  const spf = r.spf || {};
  L.push('- SPF: ' + (spf.record ? `${clip(spf.record, 110)} (${spf.all || 'no all term'}, ${spf.lookups}/10 lookups)` : 'not published'));
  const dk = r.dkim || [];
  L.push('- DKIM: ' + (dk.length
    ? dk.map(k=>`${k.selector} (${k.algo}, ~${k.bits}-bit${k.revoked ? ', revoked' : ''})`).join(', ')
    : 'no key found'));
  L.push('- DMARC: ' + (r.dmarc && r.dmarc.record ? clip(r.dmarc.record, 110) : 'not published'));
  const bl = r.blacklists || {};
  const blIp = bl.ip || [], blDom = bl.domain || [];
  const listed = blIp.flatMap(x=>x.cells || []).filter(c=>c.status === 'listed').length
               + blDom.filter(x=>x.status === 'listed').length;
  const refused = rblRefusedZones(bl);
  L.push(`- Blacklists: ${listed ? listed + ' listing(s)' : 'clean'}`
    + (refused.length ? ` (${refused.length} zone(s) inconclusive: ${refused.join(', ')})` : ''));
  const rl = r.relay || {};
  if(rl.verdict){
    L.push(`- Relay exposure: ${rl.verdict}`
      + ((rl.relays||[]).length ? ` · sending authority delegated to ${rl.relays.map(x=>x.label).join(', ')}` : ''));
  }
  const p = r.protocols || {};
  L.push(`- Protocols: MTA-STS ${p.mtasts?'yes':'no'} · TLS-RPT ${p.tlsrpt?'yes':'no'} · BIMI ${p.bimi?'yes':'no'}`);
  const ctl = r.control || {};
  const who = ctl.whois || {};
  if(who.registrar || (ctl.nameservers || []).length){
    const domainBits = [];
    if(who.registrar) domainBits.push('registrar ' + who.registrar);
    if(who.events && who.events.expiration){
      domainBits.push('expires ' + String(who.events.expiration).slice(0,10)
        + (who.days_to_expiry !== null && who.days_to_expiry !== undefined ? ` (${who.days_to_expiry} days)` : ''));
    }
    if(domainBits.length) L.push('- Domain: ' + domainBits.join(' · '));
    if((ctl.nameservers || []).length){
      L.push('- Nameservers: ' + ctl.nameservers.map(n=>n.name).join(', ')
        + (ctl.providers && ctl.providers.length ? ` (${ctl.providers.join(', ')})` : ''));
    }
    const dnskey = ctl.dnssec || {};
    L.push('- DNSSEC: ' + (dnskey.registry_signed && dnskey.dnskey_published ? 'signed & validated'
      : dnskey.dnskey_published ? 'signed (no DS published)'
      : dnskey.registry_signed ? 'DS but no DNSKEY (broken)' : 'not signed'));
  }
  L.push('');
  L.push('Generated by MX-RECON · full JSON dossier via EXPORT JSON');
  return L.join('\n');
}

function buildDiagSummary(r){
  if(!r) return '';
  const m = r.message || {};
  const L = [];
  L.push('MX-RECON — delivery diagnosis');
  L.push(`${r.domain} · analysed ${fmtWhen(r.generated)} · resolver ${plain(r.resolver)}`);
  L.push(`Risk ${r.risk}/100 (${r.verdict})`);
  L.push(`Verdict: ${plain(r.headline)}`);
  L.push('');
  const causes = r.causes || [];
  if(causes.length){
    L.push(`Findings (${causes.length}):`);
    causes.slice(0,4).forEach((c,i)=>{
      L.push(`${i+1}. [${SEV_TAGS[c.sev] || 'INFO'}] ${c.tag}: ${plain(c.title)}`);
      (c.evidence || []).slice(0,1).forEach(e=>L.push(`   - ${clip(e, 180)}`));
      if(c.fix) L.push(`   fix: ${clip(c.fix, 180)}`);
    });
    if(causes.length > 4) L.push(`   … +${causes.length - 4} more (see the full report)`);
  }else{
    L.push('Findings: none — authentication, alignment, reputation and transport all passed.');
  }
  L.push('');
  L.push('Message');
  L.push(`- from ${m.from || '?'} to ${m.to || '?'}${m.subject ? ` · "${clip(m.subject, 60)}"` : ''}`);
  const rep = r.reputation || {};
  L.push(`- sending IP ${m.sending_ip || '?'} (${m.sending_ip_source || 'unknown source'})${rep.ptr ? ` · rDNS ${rep.ptr}` : ''}`);
  const spf = r.spf || {};
  L.push(`- SPF: gateway ${spf.reported || 'n/a'} · live evaluation ${spf.evaluated || 'n/a'}${spf.mechanism ? ` (${spf.mechanism})` : ''}`);
  const dk = (r.dkim || []).filter(k=>!k.internal);
  L.push('- DKIM: ' + (dk.length
    ? dk.map(k=>`${k.selector}._domainkey.${k.domain} → ${k.dns_record ? 'published' + (k.dns_bits ? ` (~${k.dns_bits}-bit)` : '') : (k.dns_status || 'not published')}`).join('; ')
    : 'no signature found'));
  L.push('- DMARC: ' + (r.dmarc && r.dmarc.record ? clip(r.dmarc.record, 110) : 'not published'));
  const passing = r.passing || [];
  if(passing.length){
    L.push('');
    L.push(`Passed (${passing.length}): ${passing.slice(0,5).map(x=>clip(x, 90)).join(' · ')}`);
  }
  L.push('');
  L.push('Generated by MX-RECON');
  return L.join('\n');
}

function showCopyFallback(text, message){
  $('#copyPopText').value = text;
  $('#copyPopNote').textContent = message || 'select all and copy (Ctrl+C)';
  $('#copyPop').classList.remove('hide');
  document.body.style.overflow = 'hidden';
  const ta = $('#copyPopText');
  if(ta.focus) ta.focus();
  if(ta.select) ta.select();
}

function hideCopy(){
  const pop = $('#copyPop');
  if(!pop || pop.classList.contains('hide')) return;
  pop.classList.add('hide');
  document.body.style.overflow = '';
}

async function copyText(text){
  try{
    if(navigator.clipboard && window.isSecureContext){
      await navigator.clipboard.writeText(text);
      return true;
    }
  }catch(e){ /* fall through to the legacy path */ }
  try{
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly','');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    document.body.appendChild(ta);
    if(ta.select) ta.select();
    if(ta.setSelectionRange) ta.setSelectionRange(0, ta.value.length);
    const ok = document.execCommand ? document.execCommand('copy') : false;
    document.body.removeChild(ta);
    return !!ok;
  }catch(e){ return false; }
}

async function copySummary(kind){
  const text = kind === 'diag' ? buildDiagSummary(DIAG) : buildScanSummary(REPORT);
  if(!text){
    log(`nothing to summarise yet — run a ${kind === 'diag' ? 'diagnosis' : 'scan'} first`,'fail');
    return;
  }
  const size = `${text.split('\n').length} lines, ${text.length} chars`;
  const ok = await copyText(text);
  if(ok){
    log(`summary copied to clipboard (${size}) — ready to paste into email/Teams`,'ok');
  }else{
    log(`clipboard blocked by the browser — summary opened for manual copy (${size})`,'warn');
    showCopyFallback(text, `select all and copy (Ctrl+C) — ${size}`);
  }
}

$('#btnCopySummary').onclick = ()=>copySummary('scan');
$('#btnDiagCopy').onclick = ()=>copySummary('diag');
$('#copyPopCopy').onclick = async ()=>{
  const ok = await copyText($('#copyPopText').value);
  $('#copyPopNote').textContent = ok ? 'copied ✓' : 'still blocked — select the text and press Ctrl+C';
  if(ok) log('summary copied to clipboard','ok');
};
document.addEventListener('click', ev=>{
  if(ev.target.closest('[data-copy-close]')) hideCopy();
});
document.addEventListener('keydown', ev=>{
  if(ev.key === 'Escape') hideCopy();
});

/* ---------------- boot ---------------- */
(async function boot(){
  const ver = document.body.dataset.mxReconVersion || '3.x';
  log(`MX-RECON v${ver} — forensic kernel initialised (one card per row · server-side Python engine)`,'ok');
  log('modules mounted: MX · CNAME · SPF · DKIM · DMARC · PTR · RBL · MTA-STS · TLS-RPT · BIMI · INVENTORY','dns');
  $('#inResolver').addEventListener('change', onResolverChange);
  await loadResolvers();
  attachInfoButtons();
  renderRblCheck(null);
  log('record vault armed — every observed answer will be captured','dns');
  log('scan sweep armed — JS-driven, so it travels even with animations disabled','dns');
  log('armed. awaiting target… (press / to focus)','dns');
})();

/* ================================================================
   SIDEBAR NAV — scroll spy (mx, cname, spf, dkim, dmarc, ptr, rbl…)
   ================================================================ */
(function navSpy(){
  const links = $$('#sidenav a');
  if(!links.length) return;
  function mark(){
    const hrefs = [...new Set(links.map(a=>a.getAttribute('href')))];
    const visible = hrefs
      .map(h=>document.querySelector(h))
      .filter(el=>el && el.getClientRects().length > 0);
    if(!visible.length) return;
    const y = window.scrollY + 150;
    let current = visible[0];
    visible.forEach(el=>{ if(el.getBoundingClientRect().top + window.scrollY <= y) current = el; });
    links.forEach(a=>{
      const on = a.getAttribute('href') === '#' + current.id;
      a.classList.toggle('on', on);
      a.classList.toggle('live', visible.some(el=>'#' + el.id === a.getAttribute('href')));
    });
  }
  window.addEventListener('scroll', mark, {passive:true});
  window.addEventListener('resize', mark);
  mark();
  window.markSidebar = mark;
})();

/* ================================================================
   DIAGNOSTICS — "why did this email go to spam?"
   ================================================================ */
const DIAG_SAMPLE = `X-BESS-REASON: dkim
Received: from outbound9-encrypted-mta.paubox.com (outbound9-encrypted-mta.paubox.com [52.27.124.21]) by mx-inbound40-4.us-east-2c.ess.aws.cudaops.com (version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NO); Tue, 13 Oct 2026 22:06:23 +0000
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=drcfamilydentistry.com; s=paubox; t=1791929182;
 h=References:In-Reply-To:From:Date:Subject:To:From;
 b=QbO4JZ2G3yuWqMereq97QOOxR7QGuGsfmmWppTorG/sopnkO+rSeINQPCgs3sFu3p
  6d/qK7hmFW2NwsbgzLEPL8xOJtoCnFr9aKPmpNNoVDbObPRBa6KWjHpse+afyClO6J
  8aD1GhYA6eVNURNC2tU7GmLDZebQPnjJWZjWZfQc=
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com [209.85.128.71])
 (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))
 by outbound9-encrypted-mta.paubox.com (Postfix) with ESMTPS id 4j47hV3xF1z41Vk
 for <acastro@gps.dental>; Tue, 13 Oct 2026 22:06:18 +0000 (UTC)
Authentication-Results: outbound9.prod.paubox.net; arc=pass smtp.remote-ip=209.85.128.71
From: Lillian Panabaker <lillian@drcfamilydentistry.com>
Date: Tue, 13 Oct 2026 15:06:00 -0700
Message-ID: <CAJmq4Kx8cKqu1bWAe_L0CEkN-h+0MBzOWeWDT4XP2bx_7R8O4w@mail.gmail.com>
Subject: Re: Budget exclusion
To: Abigail Castro <acastro@gps.dental>
Authentication-Results: mx-inbound40-4.us-east-2c.ess.aws.cudaops.com; spf=pass (sender IP is 52.27.124.21) smtp.mailfrom=lillian@drcfamilydentistry.com; dkim=fail (No key [DKIM DNS record not found]) header.d=drcfamilydentistry.com; dmarc=none header.from=lillian@drcfamilydentistry.com
Received-SPF: pass (mx-inbound40-4.us-east-2c.ess.aws.cudaops.com: domain of lillian@drcfamilydentistry.com designates 52.27.124.21 as permitted sender)
X-BESS-BRTS-Status:1`;

let diagBusy = false, DIAG = null;

async function runDiagnosis(){
  if(diagBusy) return;
  const raw = $('#diagInput').value.trim();
  if(!raw){ log('diagnostics: paste the email headers first','fail'); $('#diagInput').focus(); return; }
  const domain = $('#diagDomain').value.trim().toLowerCase();
  diagBusy = true;
  const btn = $('#btnDiagRun');
  btn.disabled = true; $('#btnDiagTxt').textContent = 'ANALYZING';
  $('#diagResults').classList.add('hide');
  try{
    const res = await fetch('/api/diagnose', {
      method:'POST',
      headers:{'Content-Type':'application/json','X-CSRFToken':csrfToken()},
      body: JSON.stringify({headers: raw, domain, resolver: $('#inResolver').value}),
    });
    const body = await res.json();
    if(!res.ok){ throw new Error(body.error || ('HTTP '+res.status)); }
    for(const entry of body.logs){ log(entry.msg, entry.cls, entry.ts); await sleep(45); }
    DIAG = body.report;
    renderDiag(DIAG);
    $('#diagResults').classList.remove('hide');
    $$('#diagResults .card').forEach((c,i)=>{ c.classList.remove('show'); c.style.transitionDelay = (i*60)+'ms'; });
    requestAnimationFrame(()=>requestAnimationFrame(()=>$$('#diagResults .card').forEach(c=>c.classList.add('show'))));
    if(window.markSidebar) window.markSidebar();
    setTimeout(()=>$('#diag').scrollIntoView({behavior:'smooth', block:'start'}), 120);
  }catch(err){
    log('diagnosis aborted: ' + esc(err.message||err),'fail');
  }finally{
    diagBusy = false;
    btn.disabled = false; $('#btnDiagTxt').textContent = 'ANALYZE HEADERS';
  }
}

$('#btnDiagRun').onclick = runDiagnosis;
$('#btnDiagClear').onclick = ()=>{
  $('#diagInput').value = ''; $('#diagResults').classList.add('hide'); DIAG = null;
  log('diagnostics buffer flushed','dns');
};
$('#btnDiagSample').onclick = ()=>{
  $('#diagInput').value = DIAG_SAMPLE; $('#diagDomain').value = '';
  log('diagnostics: sample headers loaded','dns');
};

/* ---------------- diagnostics renderers ---------------- */
const RISK_COLOR = {CRITICAL:'var(--red)', HIGH:'var(--amber)', MODERATE:'var(--cyan)', LOW:'var(--teal)'};

function renderDiag(r){
  const color = RISK_COLOR[r.verdict] || 'var(--red)';
  const m = r.message || {};
  $('#diagVerdict').innerHTML = `
    <div>
      <div class="rl">DELIVERABILITY RISK</div>
      <div class="rv" style="color:${color}">${r.risk}<span style="font-size:14px;color:var(--faint)">/100</span></div>
    </div>
    <div>
      <div class="rl">VERDICT</div>
      <div style="font-family:var(--disp);font-size:15px;color:${color};letter-spacing:.06em">${esc(r.verdict)}</div>
    </div>
    <div class="rh">${r.headline}</div>
    <div class="rm">
      ${esc(m.from||'—')} → ${esc(m.to||'—')}<br>
      ${esc(m.subject||'(no subject)')}<br>
      target ${esc(r.domain)} · sending IP ${esc(m.sending_ip||'?')} (${esc(m.sending_ip_source||'n/a')})<br>
      ${m.hops||0} hop(s) · ${m.header_count||0} header(s) parsed · ${r.ms} ms
    </div>`;

  $('#cb-diagcauses').innerHTML = r.causes.length
    ? r.causes.map(c=>`
      <div class="cause s${c.sev}">
        <h4><span class="chip ${c.sev===0?'fail':c.sev===1?'warn':'mut'}">${SEV_TAGS[c.sev]} · ${esc(c.tag)}</span> ${c.title}</h4>
        <ul>${c.evidence.map(e=>`<li>${e}</li>`).join('')}</ul>
        <div class="fix"><b>FIX //</b> ${c.fix}</div>
      </div>`).join('')
    : `<div class="note ok"><b>No delivery-blocking problems found.</b> Authentication, alignment, reputation and transport checks all passed for this message.</div>`;
  setStatus('#st-diagcauses', r.causes.some(c=>c.sev===0)?'fail':r.causes.length?'warn':'ok',
            r.causes.length+' FINDING'+(r.causes.length===1?'':'S'));

  $('#cb-diagpass').innerHTML = r.passing.length
    ? `<ul class="passlist">${r.passing.map(p=>`<li>${p}</li>`).join('')}</ul>`
    : `<div class="note warn">No checks passed — see the findings above.</div>`;
  setStatus('#st-diagpass', r.passing.length?'ok':'warn', r.passing.length+' PASSED');

  $('#cb-diagauth').innerHTML = r.auth.length
    ? `<table class="tbl"><thead><tr><th style="width:34%">ADDED BY</th><th>SPF</th><th>DKIM</th><th>DMARC</th><th>ARC</th></tr></thead><tbody>
      ${r.auth.map(a=>{
        const cell = k => {
          const mth = (a.methods||{})[k];
          if(!mth) return '<span class="dim">—</span>';
          const cls = mth.result==='pass'?'ok':(mth.result==='fail'||mth.result==='permerror')?'fail'
                    :(mth.result==='none'||mth.result==='neutral')?'mut':'warn';
          const extra = [(mth.props||{})['header.d'], mth.reason].filter(Boolean).join(' · ');
          return `${chip(cls, esc(mth.result.toUpperCase()))}${extra?`<br><span class="dim" style="font-size:10px">${esc(extra)}</span>`:''}`;
        };
        return `<tr><td class="host">${esc(a.authserv||'—')}<br><span class="dim" style="font-size:10px">${esc(a.kind)}</span></td>
          <td>${cell('spf')}</td><td>${cell('dkim')}</td><td>${cell('dmarc')}</td><td>${cell('arc')}</td></tr>`;
      }).join('')}
      </tbody></table>
      <div class="dim mono" style="font-size:10px;margin-top:10px">destination verdict taken from: ${esc(r.final_authserv||'—')}</div>`
    : `<div class="note warn">No Authentication-Results headers were found in the pasted text.</div>`;
  setStatus('#st-diagauth', 'info', r.auth.length+' SOURCE'+(r.auth.length===1?'':'S'));

  renderDiagDkim(r.dkim);
  renderDiagSpf(r.spf);
  renderDiagHops(r.received);
  renderDiagGateway(r.gateway);
  renderDiagDns(r.dns_checks);
}

function renderDiagDkim(dkim){
  if(!dkim.length){
    $('#cb-diagdkim').innerHTML = `<div class="note warn">No DKIM-Signature headers were found in the pasted text.</div>`;
    setStatus('#st-diagdkim','warn','NONE'); return;
  }
  $('#cb-diagdkim').innerHTML = dkim.map(k=>{
    const dns = k.dns_record
      ? chip(k.dns_bits && k.dns_bits < 2048 ? 'warn' : 'ok', `PUBLISHED${k.dns_bits?` · ~${k.dns_bits}-BIT`:''}`)
      : chip('fail', esc(k.dns_status || 'NOT PUBLISHED'));
    return `<div class="cause s${k.dns_record ? 2 : 0}">
      <h4>${esc(k.selector||'?')}._domainkey.${esc(k.domain||'?')} ${k.internal?chip('mut','INTERMEDIATE HOP'):''}</h4>
      <ul>
        <li>Source header: <span class="mono">${esc(k.source)}</span></li>
        <li>Algorithm <span class="mono">${esc(k.algo)}</span>${k.canon?` · canonicalisation <span class="mono">${esc(k.canon)}</span>`:''}${k.signature_bits?` · signature implies a ~${k.signature_bits}-bit key`:''}</li>
        <li>Covers From: ${k.covers_from?chip('ok','YES'):chip('fail','NO')} · signed headers: <span class="mono">${esc((k.signed_headers||[]).join(':'))||'—'}</span></li>
        <li>DNS lookup of <span class="mono">${esc((k.selector||'?')+'.'+'_domainkey.'+(k.domain||'?'))}</span>: ${dns}
          ${k.dns_record?`<div class="mono" style="font-size:10.5px;margin-top:4px;word-break:break-all;color:var(--dim)">${esc(k.dns_record.slice(0,180))}${k.dns_record.length>180?'…':''}</div>`:''}</li>
        ${k.unknown_tags && k.unknown_tags.length?`<li>Non-standard tag(s): <span class="mono">${esc(k.unknown_tags.join(', '))}</span></li>`:''}
      </ul></div>`;
  }).join('');
  const broken = dkim.filter(k=>!k.internal && !k.dns_record).length;
  setStatus('#st-diagdkim', broken?'fail':dkim.some(k=>k.dns_bits && k.dns_bits<2048)?'warn':'ok',
            `${dkim.length} SIGNATURE${dkim.length===1?'':'S'}${broken?` · ${broken} UNVERIFIABLE`:''}`);
}

function renderDiagSpf(spf){
  const ev = spf.evaluated;
  const evChip = !ev ? chip('mut','NOT EVALUATED')
    : ev==='pass' ? chip('ok','PASS')
    : ev==='fail' ? chip('fail','FAIL')
    : ev==='softfail' ? chip('warn','SOFTFAIL')
    : ev==='neutral' ? chip('warn','NEUTRAL')
    : chip('fail', esc(ev.toUpperCase()));
  const row = (k,v)=>`<div class="kv" style="margin:0"><span class="k">${k}</span><span class="v">${v}</span></div>`;
  $('#cb-diagspf').innerHTML = `
    ${row('ENVELOPE FROM', spf.mail_from?`<span class="mono">${esc(spf.mail_from)}</span>`:'<span class="dim">—</span>')}
    ${row('SPF DOMAIN', esc(spf.domain||'—'))}
    ${row('SENDING IP', `<span class="mono">${esc(spf.ip||'—')}</span>${spf.ip_source?`<br><span class="dim" style="font-size:10px">source: ${esc(spf.ip_source)}</span>`:''}`)}
    ${row('GATEWAY VERDICT', spf.reported?chip(spf.reported==='pass'?'ok':'fail', esc(spf.reported.toUpperCase())):'<span class="dim">—</span>')}
    ${row('LIVE EVALUATION', evChip + (spf.mechanism?` <span class="dim mono" style="font-size:10px">${esc(spf.mechanism)}</span>`:''))}
    ${row('LOOKUPS USED', spf.lookups!=null?`${spf.lookups}/10`:'<span class="dim">—</span>')}
    ${spf.record?`<div class="rawbox" style="margin-top:10px"><code>${esc(spf.record)}</code><button class="copybtn" data-copy="${esc(spf.record)}">COPY</button></div>`:''}
    ${spf.trace && spf.trace.length?`<div class="dim mono" style="font-size:10px;margin-top:8px">chain: ${esc(spf.trace.join(' → '))}</div>`:''}`;
  setStatus('#st-diagspf', ev==='pass'?'ok':ev?'fail':'mut', esc((ev||'n/a').toUpperCase()));
}

function renderDiagHops(hops){
  if(!hops.length){
    $('#cb-diaghops').innerHTML = `<div class="note warn">No Received headers were found in the pasted text.</div>`;
    setStatus('#st-diaghops','warn','NONE'); return;
  }
  $('#cb-diaghops').innerHTML = hops.map((h,i)=>`
    <div class="hop">
      <div class="hh">HOP ${String(hops.length - i).padStart(2,'0')} ${h.encrypted?chip('ok','TLS'):chip('fail','PLAINTEXT')}</div>
      <div class="hb">
        from <span class="mono">${esc(h.from||'?')}</span> ${h.ip?`<span class="mono dim">[${esc(h.ip)}]</span>`:''}<br>
        by <span class="mono">${esc(h.by||'?')}</span> ${h.with?`with <span class="mono">${esc(h.with)}</span>`:''}${h.tls?` · ${esc(h.tls)}`:''}${h.cipher?` · ${esc(h.cipher)}`:''}${h.bits?` · ${h.bits} bits`:''}
        ${h.for?`<br>for <span class="mono">${esc(h.for)}</span>`:''}
        ${h.date?`<br><span class="dim">${esc(h.date)}</span>`:''}
      </div>
    </div>`).join('');
  const plain = hops.filter(h=>!h.encrypted).length;
  setStatus('#st-diaghops', plain?'warn':'ok', `${hops.length} HOP${hops.length===1?'':'S'}${plain?` · ${plain} PLAINTEXT`:''}`);
}

function renderDiagGateway(gw){
  if(!gw.length){
    $('#cb-diaggate').innerHTML = `<div class="note warn">No gateway or spam-scoring headers were found.</div>`;
    setStatus('#st-diaggate','warn','NONE'); return;
  }
  $('#cb-diaggate').innerHTML = `
    <table class="tbl"><thead><tr><th style="width:34%">HEADER</th><th>VALUE</th></tr></thead><tbody>
    ${gw.map(g=>`<tr>
      <td class="host">${esc(g.name)}${g.note?`<br><span class="dim" style="font-size:10px">${esc(g.note)}</span>`:''}</td>
      <td class="inv-val" style="word-break:break-all">${esc(g.value.length>300?g.value.slice(0,300)+'…':g.value)}</td>
    </tr>`).join('')}
    </tbody></table>`;
  setStatus('#st-diaggate','info', gw.length+' HEADER'+(gw.length===1?'':'S'));
}

function renderDiagDns(checks){
  if(!checks.length){
    $('#cb-diagdns').innerHTML = `<div class="note warn">No DNS lookups were performed.</div>`;
    setStatus('#st-diagdns','warn','0 QUERIES'); return;
  }
  $('#cb-diagdns').innerHTML = `
    <table class="tbl"><thead><tr><th style="width:42%">QUERY</th><th style="width:64px">TYPE</th><th style="width:96px">STATUS</th><th>RESULT</th></tr></thead><tbody>
    ${checks.map(c=>`<tr>
      <td class="host">${esc(c.query)}${c.note?`<br><span class="dim" style="font-size:10px">${esc(c.note)}</span>`:''}</td>
      <td><span class="tchip t-${esc(c.type)}">${esc(c.type)}</span></td>
      <td>${c.status==='NOERROR'?chip('ok','NOERROR'):c.status==='NXDOMAIN'?chip('fail','NXDOMAIN'):chip('warn',esc(c.status))}</td>
      <td class="inv-val" style="word-break:break-all">${esc(c.result)}</td>
    </tr>`).join('')}
    </tbody></table>`;
  setStatus('#st-diagdns','info', checks.length+' QUER'+(checks.length===1?'Y':'IES'));
}
