"""Fleet Manager - one .exe that provisions, migrates and monitors the VPN fleet.

Double-click it: a small local web app opens in your browser. Nothing is exposed
to the internet (it binds 127.0.0.1 only). All state lives in fleet.db beside
the exe, so accounts survive any server being replaced.
"""
import os, sys, json, time, threading, webbrowser, datetime, subprocess, urllib.parse, urllib.request, http.server, socketserver, socket
import core, engine, v2ray, v2ray_jobs
from core import q, x, now, today

VERSION = "2.0"      # bumped on every build handed out - drives the upgrade takeover

# Fixed on purpose: one app, one port, one database. FLEET_PORT is an escape
# hatch for the rare case where 8770 belongs to some other program.
PORT = int(os.environ.get("FLEET_PORT", "8770"))


# --------------------------------------------------------------- helpers
def fmt_bytes(b):
    b = float(b or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return ("%.1f %s" % (b, u)) if u != "B" else ("%d B" % b)
        b /= 1024
    return "%.1f PB" % b


def days_left(exp):
    if not exp:
        return "∞"
    try:
        d = (datetime.date.fromisoformat(exp) - datetime.date.today()).days
        return ("%dd" % d) if d >= 0 else "expired"
    except Exception:
        return "?"


def esc(s):
    import html
    return html.escape(str(s if s is not None else ""))


# ------------------------------------------------------------------- HTML
PAGE = """<!doctype html><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'>
<title>Fleet Manager</title>
<style>
:root{--bg:#0f1216;--card:#171b21;--line:#242a33;--tx:#e8ecf1;--mut:#93a0b0;--acc:#3b82f6;--ok:#22c55e;--bad:#ef4444;--warn:#f59e0b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 system-ui,Segoe UI,Arial}
.wrap{max-width:1080px;margin:0 auto;padding:18px}
h1{font-size:20px;margin:0 0 2px}h2{font-size:15px;margin:0 0 10px;color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.5px}
.sub{color:var(--mut);font-size:12px;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
label{display:block;font-size:12px;color:var(--mut);margin-bottom:3px}
input,select{background:#0d1015;border:1px solid var(--line);color:var(--tx);border-radius:7px;padding:8px 10px;font-size:13px;min-width:120px}
input:focus,select:focus{outline:0;border-color:var(--acc)}
button{background:var(--acc);color:#fff;border:0;border-radius:7px;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer}
button.ghost{background:#222833;color:var(--tx)}button.danger{background:var(--bad)}button:disabled{opacity:.45;cursor:not-allowed}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:7px 8px;border-bottom:1px solid var(--line);text-align:left}
th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase}
.tag{display:inline-block;padding:1px 7px;border-radius:20px;font-size:11px;font-weight:600}
.t-ok{background:rgba(34,197,94,.15);color:var(--ok)}.t-bad{background:rgba(239,68,68,.15);color:var(--bad)}
.t-ir{background:rgba(245,158,11,.15);color:var(--warn)}.t-fg{background:rgba(59,130,246,.15);color:var(--acc)}
.tabs{display:flex;gap:4px;margin-bottom:14px;flex-wrap:wrap}
.tabs button{background:#1b212a;color:var(--mut)}.tabs button.on{background:var(--acc);color:#fff}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:14px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.kpi b{display:block;font-size:22px;margin-top:2px}
.kpi span{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.4px}
pre{background:#0a0d11;border:1px solid var(--line);border-radius:8px;padding:10px;max-height:280px;overflow:auto;font-size:12px;white-space:pre-wrap;color:#c9d4e0}
.bar{background:#0a0d11;border-radius:20px;height:20px;overflow:hidden;border:1px solid var(--line)}
.fill{height:100%;background:linear-gradient(90deg,#2563eb,#3b82f6);color:#fff;font-size:11px;text-align:center;line-height:20px;width:0}
.mono{font-family:Consolas,monospace;font-size:12px}
.hint{font-size:12px;color:var(--mut);margin-top:6px}
.keybox{display:flex;gap:6px;margin-top:6px}
.keybox input{flex:1;font-family:Consolas,monospace;font-size:11px}
dialog{background:var(--card);color:var(--tx);border:1px solid var(--line);border-radius:12px;padding:18px;max-width:560px}
dialog::backdrop{background:rgba(0,0,0,.6)}
.mini{font-size:12px;color:var(--mut)}
.chk{display:flex;align-items:center;gap:6px;font-size:13px;padding:3px 0}
</style>
<div class=wrap>
<h1>Fleet Manager <span id=ver class=mini style="font-size:12px;color:var(--mut);font-weight:400"></span></h1>
<div class=sub>Provision, migrate and monitor your VPN servers
 &nbsp;&middot;&nbsp; <span id=syncdot style="color:var(--mut)">&#9679;</span> <span id=syncmsg class=mini>connecting...</span></div>
<div class=tabs>
  <button data-t=dash class=on onclick=tab('dash')>Dashboard</button>
  <button data-t=servers onclick=tab('servers')>Servers</button>
  <button data-t=build onclick=tab('build')>New service</button>
  <button data-t=v2ray onclick=tab('v2ray')>v2ray</button>
  <button data-t=users onclick=tab('users')>Users</button>
  <button data-t=migrate onclick=tab('migrate')>Replace a server</button>
</div>
<div id=view></div>
<div class=card id=jobcard style=display:none>
  <h2>Progress</h2>
  <div class=bar><div class=fill id=fill>0%</div></div>
  <div id=jstep class=hint></div>
  <pre id=jlog></pre>
</div>
</div>
<dialog id=dlg><h3 id=dt style=margin:.2rem_0></h3><p id=dm style=color:var(--mut);font-size:13px;white-space:pre-wrap></p>
<button class=ghost onclick="dlg.close();load()">OK</button></dialog>
<script>
var S={}, cur='dash';
function tab(t){cur=t;document.querySelectorAll('.tabs button').forEach(b=>b.classList.toggle('on',b.dataset.t==t));load();}
function api(p,d){return fetch(p,{method:d?'POST':'GET',body:d?new URLSearchParams(d):null}).then(r=>r.json());}
function load(){api('/api/state').then(s=>{S=s;render();});}
function esc(x){return (x===null||x===undefined)?'':String(x).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function render(){
  var sy=S.sync||{};
  var vv=document.getElementById('ver'); if(vv)vv.textContent='v'+(S.version||'?');
  var d=document.getElementById('syncdot'), m=document.getElementById('syncmsg');
  if(d){d.style.color=sy.ok?'var(--ok)':'var(--warn)';
        m.textContent=(sy.msg||'')+(sy.ts?(' \\u00b7 '+sy.ts.replace('T',' ').slice(5)):'');}
  var v=document.getElementById('view');
  if(cur=='dash')v.innerHTML=dash();
  else if(cur=='servers')v.innerHTML=servers();
  else if(cur=='build')v.innerHTML=build();
  else if(cur=='v2ray')v.innerHTML=v2rayTab();
  else if(cur=='users')v.innerHTML=users();
  else v.innerHTML=migrate();
  if(cur=='dash')drawChart();
}
function dash(){
  var k=S.kpi||{};
  var h='<div class=kpis>'
   +kpi('Servers',k.servers||0)+kpi('Services',k.services||0)+kpi('Users',k.users||0)
   +kpi('Total traffic',k.total_h||'0 B')+kpi('Online now',k.live||0)+'</div>';
  h+='<div class=card><h2>Traffic over time</h2><canvas id=cv height=170></canvas>'
   +'<div class=hint id=cvhint></div></div>';
  h+='<div class=card><h2>Services</h2><table><tr><th>name</th><th>Iran server</th><th>foreign exit</th><th>users</th><th>traffic</th><th>status</th><th></th></tr>';
  (S.services||[]).forEach(function(s){
    h+='<tr><td>'+esc(s.name)+'</td><td class=mono>'+esc(s.iran_ip)+'</td><td class=mono>'+esc(s.foreign_ip)+'</td>'
     +'<td>'+s.user_count+'</td><td>'+esc(s.total_h)+'</td>'
     +'<td><span class="tag '+(s.status=='live'?'t-ok':'t-bad')+'">'+esc(s.status)+'</span></td>'
     +'<td><button class=ghost onclick="refresh('+s.id+')">refresh</button> '
     +(s.panel?'<a href="'+esc(s.panel)+'" target=_blank><button class=ghost>panel</button></a> ':'')
     +'<a href="/api/ovpn?service='+s.id+'"><button class=ghost>.ovpn</button></a></td></tr>';
    h+='<tr><td colspan=7 class=mini style=padding-top:0>'
     +(s.note=='direct'?'&nbsp;&nbsp;<b style="color:var(--warn)">DIRECT</b> (no Iran relay) &nbsp;&middot;&nbsp; ':'')
     +'&nbsp;&nbsp;OpenVPN: <span class=mono>'+esc(s.iran_ip)+':1194</span>'
     +(s.panel_user?' &nbsp;&middot;&nbsp; panel login: <span class=mono>'+esc(s.panel_user)+' / '+esc(s.panel_pass)+'</span>':'')
     +(s.l2tp_psk?' &nbsp;&middot;&nbsp; L2TP PSK: <span class=mono>'+esc(s.l2tp_psk)+'</span>':'')
     +'</td></tr>';
  });
  if(!(S.services||[]).length)h+='<tr><td colspan=7 class=mini>No service yet &mdash; use <b>New service</b>.</td></tr>';
  h+='</table></div>';
  h+='<div class=card><h2>Recent activity</h2><table>';
  (S.events||[]).forEach(e=>{h+='<tr><td class=mono style=width:150px>'+esc(e.ts)+'</td><td>'+esc(e.kind)+'</td><td>'+esc(e.msg)+'</td></tr>';});
  h+='</table></div>';
  return h;
}
function kpi(t,v){return '<div class=kpi><span>'+t+'</span><b>'+esc(v)+'</b></div>';}
function drawChart(){
  var c=document.getElementById('cv'); if(!c)return;
  var pts=S.chart||[]; var W=c.width=c.clientWidth, H=c.height, g=c.getContext('2d');
  g.clearRect(0,0,W,H);
  document.getElementById('cvhint').textContent = pts.length<2 ? 'Collecting data - the graph fills in as usage is recorded (click refresh on a service).' : (pts.length+' samples, '+pts[0].ts+' -> '+pts[pts.length-1].ts);
  if(pts.length<2)return;
  var mx=Math.max.apply(null,pts.map(p=>p.v))||1, pad=28;
  g.strokeStyle='#242a33';g.lineWidth=1;
  for(var i=0;i<=4;i++){var y=pad+(H-2*pad)*i/4;g.beginPath();g.moveTo(pad,y);g.lineTo(W-6,y);g.stroke();}
  g.beginPath();
  pts.forEach(function(p,i){
    var xx=pad+(W-pad-8)*i/(pts.length-1), yy=H-pad-(H-2*pad)*(p.v/mx);
    i?g.lineTo(xx,yy):g.moveTo(xx,yy);
  });
  g.strokeStyle='#3b82f6';g.lineWidth=2;g.stroke();
  g.lineTo(W-8,H-pad);g.lineTo(pad,H-pad);g.closePath();
  var grd=g.createLinearGradient(0,0,0,H);grd.addColorStop(0,'rgba(59,130,246,.35)');grd.addColorStop(1,'rgba(59,130,246,0)');
  g.fillStyle=grd;g.fill();
  g.fillStyle='#93a0b0';g.font='11px system-ui';
  g.fillText(S.chart_max_h||'',4,pad-8);
}
function servers(){
  var h='<div class=card><h2>Add a server</h2>'
   +'<div class=row>'
   +'<div><label>IP address</label><input id=sip placeholder=1.2.3.4></div>'
   +'<div><label>SSH user</label><input id=suser value=root style=width:110px></div>'
   +'<div><label>Login</label><select id=smethod onchange=authui()><option value=password>Password</option><option value=key>Fleet key (no password)</option></select></div>'
   +'<div id=spwbox><label>Password</label><input id=spass type=password></div>'
   +'<div><button onclick=checkServer()>Check &amp; add</button></div></div>'
   +'<div class=hint>The app connects, detects automatically whether it is an <b>Iran</b> or <b>foreign</b> server, and checks it can run a VPN.</div>'
   +'<div class=hint style=margin-top:10px><b>Fleet key</b> &mdash; if a server has no password login, run this one line on it, then pick "Fleet key":</div>'
   +'<div class=keybox><input readonly id=fkey value="'+esc(S.key_cmd||'')+'" onclick=this.select()><button class=ghost onclick=cp()>Copy</button></div>'
   +'<div id=sres class=hint></div></div>';
  h+='<div class=card><h2>Known servers</h2><table><tr><th>IP</th><th>role</th><th>location</th><th>status</th><th>panel</th><th></th></tr>';
  (S.servers||[]).forEach(function(s){
    h+='<tr><td class=mono>'+esc(s.ip)+'</td>'
     +'<td><span class="tag '+(s.role=='iran'?'t-ir':'t-fg')+'">'+esc(s.role||'?')+'</span> '
     +'<button class=ghost style=padding:1px_6px;font-size:11px onclick="setRole('+s.id+',\\''+(s.role=='iran'?'foreign':'iran')+'\\')">&#8644;</button></td>'
     +'<td class=mini>'+esc((s.country||'')+' '+(s.city||''))+'</td>'
     +'<td>'+esc(s.status)+'</td>'
     +'<td class=mini>'+(s.panel_port?('<span class=mono>'+esc(s.panel_user)+' / '+esc(s.panel_pass)+'</span>'):'-')+'</td>'
     +'<td><button class=danger onclick="delServer('+s.id+')">remove</button></td></tr>';
  });
  h+='</table></div>';
  return h;
}
function authui(){document.getElementById('spwbox').style.display=document.getElementById('smethod').value=='password'?'block':'none';}
function cp(){var e=document.getElementById('fkey');e.select();document.execCommand('copy');}
function checkServer(){
  var d={ip:sip.value.trim(),user:suser.value.trim()||'root',method:smethod.value,secret:(document.getElementById('spass')||{}).value||''};
  if(!d.ip){alert('Enter the IP');return;}
  sres.textContent='Checking...';
  api('/api/check',d).then(r=>{sres.innerHTML=(r.ok?'<span style=color:var(--ok)>':'<span style=color:var(--bad)>')+esc(r.msg)+'</span>';if(r.ok)load();});
}
function delServer(id){if(confirm('Remove this server from the app? (the server itself is not touched)'))api('/api/server-del',{id:id}).then(load);}
function setRole(id,r){api('/api/server-role',{id:id,role:r}).then(load);}
function build(){
  var ir=(S.servers||[]).filter(s=>s.role=='iran'), fg=(S.servers||[]).filter(s=>s.role=='foreign');
  var h='<div class=card><h2>Build a new service</h2>'
   +'<div class=row>'
   +'<div><label>Iran server (customers connect here)</label>'+sel('bir',ir)+'</div>'
   +'<div><label>Foreign server (traffic exits here)</label>'+sel('bfg',fg)+'</div>'
   +'<div><label>Service name</label><input id=bname placeholder="my service"></div>'
   +'</div><div class=row style=margin-top:10px>'
   +'<div><label>Panel user</label><input id=bpu value=admin style=width:120px></div>'
   +'<div><label>Panel password (blank = auto)</label><input id=bpp style=width:180px></div>'
   +'<div><label>Copy users from</label>'+selService('bcopy',true)+'</div>'
   +'<div><button onclick=doBuild()>Install everything</button></div></div>'
   +'<div class=hint>Installs OpenVPN + L2TP + the user panel on the Iran box, the tunnel on the foreign box, wires them together, then <b>verifies the whole chain</b> and reports.</div></div>';
  h+='<div class=card style="border-color:#5b4a1f"><h2>Iran servers blocked? Build a DIRECT service</h2>'
   +'<div class=row>'
   +'<div><label>Foreign server (customers connect here AND exit here)</label>'+sel('dfg',fg)+'</div>'
   +'<div><label>Service name</label><input id=dname placeholder="direct service"></div>'
   +'<div><label>Panel user</label><input id=dpu value=admin style=width:110px></div>'
   +'<div><label>Panel password (blank = auto)</label><input id=dpp style=width:170px></div>'
   +'<div><label>Copy users from</label>'+selService('dcopy',true)+'</div>'
   +'<div><button onclick=doDirect()>Build direct service</button></div></div>'
   +'<div class=hint>No Iran relay at all: OpenVPN + L2TP + the panel run on the foreign server and customers dial it straight, '
   +'keeping their data used and days left. Use this when the domestic servers are filtered. '
   +'<b>Trade-off:</b> the connection goes abroad with nothing domestic in front of it, so it is easier for an ISP to spot and block than the relay setup &mdash; expect to swap the IP more often.</div></div>';
  h+='<div class=card><h2>Already have a running DIRECT server?</h2>'
   +'<div class=row><div><label>Foreign server</label>'+sel('adfg',fg)+'</div>'
   +'<div><button class=ghost onclick=doAdoptDirect()>Import it</button></div></div>'
   +'<div class=hint>For a box already set up (e.g. with <span class=mono>setup-direct.sh</span>): reads its panel login and its accounts '
   +'into the app <b>without reinstalling anything</b>.</div></div>';
  h+='<div class=card><h2>Already have a running pair?</h2>'
   +'<div class=row><div><label>Iran server</label>'+sel('air',ir)+'</div>'
   +'<div><label>Foreign server</label>'+sel('afg',fg)+'</div>'
   +'<div><button class=ghost onclick=doAdopt()>Import it</button></div></div>'
   +'<div class=hint>Reads the existing accounts and tunnel settings into the app <b>without reinstalling</b>, so you can manage and migrate it from here.</div></div>';
  return h;
}
function sel(id,list){var h='<select id='+id+'>';list.forEach(s=>{h+='<option value='+s.id+'>'+esc(s.ip)+' ('+esc(s.country||s.role)+')</option>';});return h+'</select>';}
function selService(id,blank){var h='<select id='+id+'>'+(blank?'<option value="">- none -</option>':'');(S.services||[]).forEach(s=>{h+='<option value='+s.id+'>'+esc(s.name)+' ('+s.user_count+' users)</option>';});return h+'</select>';}
function doBuild(){
  if(!bir.value||!bfg.value){alert('Add an Iran server and a foreign server first (Servers tab).');return;}
  showJob();
  api('/api/build',{iran:bir.value,foreign:bfg.value,name:bname.value,puser:bpu.value,ppass:bpp.value,copy_from:bcopy.value}).then(poll);
}
function doDirect(){
  if(!dfg.value){alert('Add a foreign server first (Servers tab).');return;}
  if(!confirm('Install OpenVPN + panel directly on that foreign server?\n\nCustomers will connect straight to it - no Iran relay.'))return;
  showJob();
  api('/api/build-direct',{foreign:dfg.value,name:dname.value,puser:dpu.value,ppass:dpp.value,copy_from:dcopy.value}).then(poll);
}
function v2rayTab(){
  var fg=(S.servers||[]).filter(s=>s.role=='foreign');
  var svcs=(S.services||[]).filter(s=>s.kind=='v2ray');
  var probe=(S.servers||[]).filter(s=>s.is_probe);
  var h='<div class=card style="border-color:#1f5b3a"><h2>Build a v2ray service (works from Iran)</h2>'
   +'<div class=row>'
   +'<div><label>Foreign server</label>'+sel('vfg',fg)+'</div>'
   +'<div><label>Service name</label><input id=vname placeholder="my v2ray"></div>'
   +'<div><label>Bring accounts from</label>'+selService('vcopy',true)+'</div>'
   +'<div><button onclick=doV2ray()>Install</button></div></div>'
   +'<div class=hint>Installs the panel and four entry protocols on that one server: '
   +'<b>VLESS-REALITY</b> 443 &middot; <b>Trojan-REALITY</b> 8443 &middot; <b>VMess</b> 8080 &middot; <b>Shadowsocks</b> 8388. '
   +'Each customer gets ONE subscription link containing all four, so when an ISP blocks one they switch inside their app. '
   +'OpenVPN is not offered here on purpose &mdash; on the Iran path it is identified and reset no matter the port.</div></div>';

  h+='<div class=card><h2>Iran probe &mdash; how we know a server is not filtered</h2>';
  if(probe.length){
    h+='<div class=mini>Using <span class=mono>'+esc(probe[0].ip)+'</span> to test reachability from inside Iran. '
      +'It is only ever asked to open a TCP port; nothing is installed on it. '
      +'<button class=ghost onclick="setProbe(0)">stop using it</button></div>';
  } else {
    h+='<div class=row><div><label>An Iran server to test from</label>'
      +sel('vprobe',(S.servers||[]).filter(s=>s.role=='iran'))+'</div>'
      +'<div><button class=ghost onclick=setProbeSel()>Use as probe</button></div></div>'
      +'<div class=hint>Without this, nobody can tell whether a new server is already blocked in Iran until customers complain. '
      +'Add any Iran box in the Servers tab and select it here &mdash; it carries no traffic.</div>';
  }
  h+='</div>';

  h+='<div class=card><h2>v2ray services</h2>';
  if(!svcs.length){ h+='<div class=mini>None yet.</div>'; }
  else{
    h+='<table><tr><th>name</th><th>server</th><th>users</th><th>traffic</th><th>status</th><th></th></tr>';
    svcs.forEach(function(s){
      h+='<tr><td>'+esc(s.name)+'</td><td class=mono>'+esc(s.foreign_ip)+'</td><td>'+s.user_count+'</td>'
       +'<td>'+esc(s.total_h)+'</td><td><span class="tag '+(s.status=='live'?'t-ok':'t-bad')+'">'+esc(s.status)+'</span></td>'
       +'<td><button class=ghost onclick="testV2('+s.id+')">test now</button> '
       +(s.panel_url?'<a href="'+esc(s.panel_url)+'" target=_blank><button class=ghost>panel</button></a>':'')+'</td></tr>';
      h+='<tr><td colspan=6 class=mini style=padding-top:0>&nbsp;&nbsp;panel login: <span class=mono>'
       +esc(s.panel_user||'')+' / '+esc(s.panel_pass||'')+'</span></td></tr>';
    });
    h+='</table>';
  }
  h+='</div>';

  h+='<div class=card><h2>Accounts</h2>';
  if(!svcs.length){ h+='<div class=mini>Build a service first.</div>'; }
  else{
    h+='<div class=row><div><label>Service</label><select id=vsvc onchange=load()>'
     +svcs.map(s=>'<option value='+s.id+'>'+esc(s.name)+'</option>').join('')+'</select></div>'
     +'<div><label>Username</label><input id=vu placeholder="customer1" style=width:150px></div>'
     +'<div><label>GB (0=unlimited)</label><input id=vgb type=number min=0 step=1 value=0 style=width:130px></div>'
     +'<div><label>Days (0=unlimited)</label><input id=vd type=number min=0 value=30 style=width:130px></div>'
     +'<div><button onclick=addV2User()>Add / update</button></div></div>';
    var sid=(document.getElementById('vsvc')||{}).value||svcs[0].id;
    var us=(S.users||[]).filter(u=>String(u.service_id)==String(sid));
    h+='<table><tr><th>user</th><th>expires</th><th>used</th><th>limit</th><th>status</th><th>subscription</th><th></th></tr>';
    us.forEach(function(u){
      h+='<tr><td>'+esc(u.username)+'</td><td>'+esc(u.days_left)+'</td><td>'+esc(u.used_h)+'</td>'
       +'<td>'+(u.limit_gb?esc(u.limit_gb)+' GB':'&infin;')+'</td>'
       +'<td><span class="tag '+(u.enabled?'t-ok':'t-bad')+'">'+(u.enabled?'active':'off')+'</span></td>'
       +'<td>'+(u.sub_url?'<button class=ghost onclick="copyTxt(\''+esc(u.sub_url)+'\',this)">copy link</button>':'-')+'</td>'
       +'<td><button class=ghost onclick="v2act('+sid+',\''+esc(u.username)+'\',\'toggle\')">on/off</button> '
       +'<button class=ghost onclick="v2act('+sid+',\''+esc(u.username)+'\',\'reset\')">reset data</button> '
       +'<button class=danger onclick="v2act('+sid+',\''+esc(u.username)+'\',\'del\')">delete</button></td></tr>';
    });
    h+='</table><div class=hint>The subscription link carries all four protocols. If a customer says it stopped working, '
     +'have them refresh the subscription in their app first &mdash; after a server move the same link picks up the new address.</div>';
  }
  h+='</div>';

  if(svcs.length){
    h+='<div class=card style="border-color:#5b4a1f"><h2>Server got filtered? Move the service</h2><div class=row>'
     +'<div><label>Service</label><select id=vmsvc>'
     +svcs.map(s=>'<option value='+s.id+'>'+esc(s.name)+' ('+esc(s.foreign_ip)+')</option>').join('')+'</select></div>'
     +'<div><label>New foreign server</label>'+sel('vmnew',fg)+'</div>'
     +'<div><button onclick=moveV2()>Move everything</button></div></div>'
     +'<div class=hint>Rebuilds on the new server and brings every account with its used data and remaining days &mdash; '
     +'even if the old server is already dead. The REALITY identity and panel login are carried over, then it tests the '
     +'new server (including from Iran) before calling it live.</div></div>';
  }
  return h;
}
function copyTxt(t,btn){navigator.clipboard&&navigator.clipboard.writeText(t);var o=btn.textContent;btn.textContent='copied';setTimeout(()=>btn.textContent=o,1200);}
function doV2ray(){
  if(!vfg.value){alert('Add a foreign server first (Servers tab).');return;}
  showJob();api('/api/v2ray-build',{foreign:vfg.value,name:vname.value,copy_from:vcopy.value}).then(poll);
}
function testV2(id){showJob();api('/api/v2ray-test',{service:id}).then(poll);}
function addV2User(){
  var sid=document.getElementById('vsvc').value;
  if(!vu.value){alert('Enter a username');return;}
  api('/api/v2ray-user-add',{service:sid,username:vu.value,gb:vgb.value,days:vd.value}).then(function(r){
    if(r.err)alert(r.err); vu.value=''; load();});
}
function v2act(sid,u,a){
  if(a=='del'&&!confirm('Delete '+u+'?'))return;
  api('/api/v2ray-user-act',{service:sid,username:u,action:a}).then(load);
}
function moveV2(){
  if(!vmnew.value){alert('Pick the new server.');return;}
  if(!confirm('Move the service to that server? Customers keep their accounts; the address changes.'))return;
  showJob();api('/api/v2ray-move',{service:vmsvc.value,foreign:vmnew.value}).then(poll);
}
function setProbeSel(){ if(!vprobe.value){alert('Add an Iran server first.');return;} setProbe(vprobe.value); }
function setProbe(id){ api('/api/set-probe',{id:id}).then(load); }

function doAdoptDirect(){
  if(!adfg.value){alert('Pick the foreign server.');return;}
  showJob();api('/api/adopt-direct',{foreign:adfg.value}).then(poll);
}
function doAdopt(){
  if(!air.value||!afg.value){alert('Pick both servers.');return;}
  showJob();api('/api/adopt',{iran:air.value,foreign:afg.value}).then(poll);
}
function users(){
  var h='<div class=card><h2>Accounts</h2><div class=row>'
   +'<div><label>Service</label>'+selService('usvc')+'</div>'
   +'<div><label>Username</label><input id=un></div>'
   +'<div><label>Password</label><input id=up></div>'
   +'<div><label>Days (0=∞)</label><input id=ud type=number value=30 style=width:100px></div>'
   +'<div><label>GB (0=∞)</label><input id=ug type=number value=50 style=width:100px></div>'
   +'<div><label>Devices (0=∞)</label><input id=uc type=number value=1 style=width:110px></div>'
   +'<div><button onclick=addUser()>Add / update</button></div></div></div>';
  h+='<div class=card><table><tr><th>service</th><th>user</th><th>password</th><th>days left</th><th>used</th><th>limit</th><th>devices</th><th>status</th><th></th></tr>';
  (S.users||[]).forEach(function(u){
    h+='<tr><td class=mini>'+esc(u.service_name)+'</td><td>'+esc(u.username)+'</td><td class=mono>'+esc(u.password)+'</td>'
     +'<td>'+esc(u.days_left)+'</td><td>'+esc(u.used_h)+'</td><td>'+(u.limit_gb?esc(u.limit_gb)+' GB':'∞')+'</td>'
     +'<td>'+(u.max_conn||'∞')+'</td>'
     +'<td><span class="tag '+(u.enabled?'t-ok':'t-bad')+'">'+(u.enabled?'on':'off')+'</span></td>'
     +'<td><button class=ghost onclick="uact('+u.id+',\\'toggle\\')">toggle</button> '
     +'<button class=ghost onclick="uact('+u.id+',\\'reset\\')">reset data</button> '
     +'<button class=danger onclick="uact('+u.id+',\\'del\\')">delete</button></td></tr>';
  });
  if(!(S.users||[]).length)h+='<tr><td colspan=9 class=mini>No accounts yet.</td></tr>';
  h+='</table></div>';
  return h;
}
function addUser(){
  if(!usvc.value){alert('Create a service first.');return;}
  api('/api/user-add',{service:usvc.value,username:un.value,password:up.value,days:ud.value,gb:ug.value,conns:uc.value}).then(r=>{if(r.err)alert(r.err);load();});
}
function uact(id,a){if(a=='del'&&!confirm('Delete this account?'))return;api('/api/user-act',{id:id,action:a}).then(load);}
function migrate(){
  var ir=(S.servers||[]).filter(s=>s.role=='iran'), fg=(S.servers||[]).filter(s=>s.role=='foreign');
  var direct=(S.services||[]).filter(s=>s.note=='direct');
  var h='';
  if(direct.length){
    h+='<div class=card style="border-color:#5b4a1f"><h2>Move a DIRECT service to a new server</h2><div class=row>'
     +'<div><label>Direct service</label><select id=mdsvc>'
     +direct.map(s=>'<option value='+s.id+'>'+esc(s.name)+' ('+esc(s.iran_ip)+', '+s.user_count+' users)</option>').join('')
     +'</select></div>'
     +'<div><label>New foreign server</label>'+sel('mdnew',fg)+'</div>'
     +'<div><button onclick=doRepDirect()>Move it</button></div></div>'
     +'<div class=hint>Rebuilds everything on the new box and brings every account over <b>with its data used and days left</b> '
     +'&mdash; even if the old server is already dead. Afterwards give customers the new IP and re-download the .ovpn.</div></div>';
  }
  h+='<div class=card><h2>Replace the FOREIGN server (exit got filtered)</h2><div class=row>'
   +'<div><label>Service</label>'+selService('mfsvc')+'</div>'
   +'<div><label>New foreign server</label>'+sel('mfnew',fg)+'</div>'
   +'<div><button onclick=doRepFg()>Swap the exit</button></div></div>'
   +'<div class=hint>Users stay on the same Iran address &mdash; nothing changes for them, and <b>traffic used + days left are kept</b>.</div></div>';
  h+='<div class=card><h2>Replace the IRAN server</h2><div class=row>'
   +'<div><label>Service</label>'+selService('misvc')+'</div>'
   +'<div><label>New Iran server</label>'+sel('minew',ir)+'</div>'
   +'<div><button onclick=doRepIr()>Rebuild on the new server</button></div></div>'
   +'<div class=hint>Rebuilds the full stack and restores every account <b>with its used data and remaining days</b>. Pick which accounts to bring over below (default: all).</div>'
   +'<div id=userpick class=hint style=margin-top:8px></div>'
   +'<div class=hint style=color:var(--warn)>Note: clients must be given the new Iran IP, since the old address is gone.</div></div>';
  return h;
}
function doRepFg(){if(!mfsvc.value||!mfnew.value){alert('Pick a service and a new foreign server.');return;}showJob();api('/api/replace-foreign',{service:mfsvc.value,foreign:mfnew.value}).then(poll);}
function doRepDirect(){
  if(!mdsvc.value||!mdnew.value){alert('Pick a direct service and a new foreign server.');return;}
  var s=(S.services||[]).filter(x=>x.id==mdsvc.value)[0]||{}, n=(S.servers||[]).filter(x=>x.id==mdnew.value)[0]||{};
  if(!confirm('Move '+(s.name||'')+' from '+(s.iran_ip||'')+' to '+(n.ip||'')+'?\n\nCustomers must be given the new address afterwards.'))return;
  showJob();api('/api/replace-direct',{service:mdsvc.value,foreign:mdnew.value}).then(poll);
}
function doRepIr(){if(!misvc.value||!minew.value){alert('Pick a service and a new Iran server.');return;}
  if(!confirm('Rebuild the service on the new Iran server? Accounts keep their data and days.'))return;
  showJob();api('/api/replace-iran',{service:misvc.value,iran:minew.value}).then(poll);}
function refresh(id){api('/api/refresh',{service:id}).then(load);}
function showJob(){document.getElementById('jobcard').style.display='block';document.getElementById('jlog').textContent='';}
function poll(){
  api('/api/job').then(function(j){
    fill.style.width=j.percent+'%';fill.textContent=j.percent+'%';
    document.getElementById('jstep').textContent=j.step||'';
    var L=document.getElementById('jlog');L.textContent=(j.log||[]).join('\\n');L.scrollTop=L.scrollHeight;
    if(!j.done){setTimeout(poll,900);}
    else{dt.textContent=j.ok?'Done':'Needs attention';dm.textContent=j.result||'';dlg.showModal();}
  });
}
load();
// keep every tab live. Skip a redraw while someone is typing or a dropdown is
// open, otherwise the refresh would wipe what they are in the middle of entering.
setInterval(function(){
  var a=document.activeElement;
  if(a&&(a.tagName=='INPUT'||a.tagName=='SELECT'||a.tagName=='TEXTAREA'))return;
  if(document.getElementById('dlg').open)return;
  load();
},5000);
</script>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _form(self):
        n = int(self.headers.get("Content-Length", 0))
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if p == "/":
            b = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif p == "/api/ping":
            b = ("fleet-manager %s" % VERSION).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif p == "/api/quit":
            # a NEWER copy asking this one to step aside (loopback only)
            b = b"bye"
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            threading.Thread(target=lambda: (time.sleep(0.4), os._exit(0)), daemon=True).start()
        elif p == "/api/state":
            self._json(state())
        elif p == "/api/job":
            self._json(engine.jsnapshot())
        elif p == "/api/ovpn":
            # fetch the shared client profile off the Iran server so support can
            # hand it to a customer without ever opening an SSH session
            try:
                sid = int(urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("service", ["0"])[0])
                svc = q("SELECT * FROM services WHERE id=?", (sid,), one=True)
                iran = q("SELECT * FROM servers WHERE id=?", (svc["iran_id"],), one=True)
                with core.SSH(iran["ip"], iran["ssh_user"], iran["auth_method"], iran["secret"]) as s:
                    pu = iran.get("panel_user") or "admin"
                    pp = iran.get("panel_pass") or ""
                    port = iran.get("panel_port") or 2098
                    prof = s.run("curl -sk -u '%s:%s' https://127.0.0.1:%s/ovpn" % (pu, pp, port), timeout=40)
                if not prof or "remote" not in prof:
                    raise RuntimeError("could not read the profile from the server")
                b = prof.encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-openvpn-profile")
                self.send_header("Content-Disposition", 'attachment; filename="%s.ovpn"' % iran["ip"])
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
            except Exception as e:
                b = ("could not fetch the .ovpn: %s" % e).encode()
                self.send_response(500)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        f = self._form()
        try:
            if p == "/api/check":
                r = core.probe(f.get("ip", "").strip(), f.get("user", "root"),
                               f.get("method", "password"), f.get("secret", ""))
                if r["ok"]:
                    d = r["detail"]
                    ex = q("SELECT id FROM servers WHERE ip=?", (f["ip"].strip(),), one=True)
                    if ex:
                        x("UPDATE servers SET ssh_user=?,auth_method=?,secret=?,role=?,country=?,city=?,isp=?,"
                          "status='ready',last_seen=? WHERE id=?",
                          (f.get("user", "root"), f.get("method"), f.get("secret", ""), r["role"],
                           d.get("country"), d.get("city"), d.get("isp"), now(), ex["id"]))
                    else:
                        x("INSERT INTO servers(ip,ssh_user,auth_method,secret,role,country,city,isp,status,added_at,last_seen)"
                          " VALUES(?,?,?,?,?,?,?,?, 'ready',?,?)",
                          (f["ip"].strip(), f.get("user", "root"), f.get("method"), f.get("secret", ""),
                           r["role"], d.get("country"), d.get("city"), d.get("isp"), now(), now()))
                    core.log_event("server", "added %s as %s" % (f["ip"], r["role"]))
                self._json(r)
            elif p == "/api/server-del":
                x("DELETE FROM servers WHERE id=?", (f["id"],))
                self._json({"ok": True})
            elif p == "/api/server-role":
                # manual override, in case auto-detection got it wrong
                x("UPDATE servers SET role=? WHERE id=?", (f["role"], f["id"]))
                self._json({"ok": True})
            elif p == "/api/build":
                engine.job_new_service(int(f["iran"]), int(f["foreign"]), f.get("name"),
                                       f.get("puser") or "admin", f.get("ppass") or None,
                                       int(f["copy_from"]) if f.get("copy_from") else None)
                self._json({"ok": True})
            elif p == "/api/build-direct":
                engine.job_direct_service(int(f["foreign"]), f.get("name"),
                                          f.get("puser") or "admin", f.get("ppass") or None,
                                          int(f["copy_from"]) if f.get("copy_from") else None)
                self._json({"ok": True})
            elif p == "/api/v2ray-build":
                v2ray_jobs.job_build(int(f["foreign"]), f.get("name"),
                                     int(f["copy_from"]) if f.get("copy_from") else None)
                self._json({"ok": True})
            elif p == "/api/v2ray-move":
                v2ray_jobs.job_replace(int(f["service"]), int(f["foreign"]))
                self._json({"ok": True})
            elif p == "/api/v2ray-test":
                v2ray_jobs.job_test(int(f["service"]))
                self._json({"ok": True})
            elif p == "/api/v2ray-user-add":
                try:
                    v2ray.add_user(int(f["service"]), f["username"].strip(), f.get("gb") or 0, f.get("days") or 0)
                    self._json({"ok": True})
                except Exception as e:
                    self._json({"err": str(e)})
            elif p == "/api/v2ray-user-act":
                try:
                    v2ray.user_action(int(f["service"]), f["username"], f["action"])
                    self._json({"ok": True})
                except Exception as e:
                    self._json({"err": str(e)})
            elif p == "/api/set-probe":
                # only one probe at a time; 0 clears it
                x("UPDATE servers SET is_probe=0")
                if f.get("id") and f["id"] != "0":
                    x("UPDATE servers SET is_probe=1 WHERE id=?", (int(f["id"]),))
                self._json({"ok": True})
            elif p == "/api/adopt-direct":
                engine.job_adopt_direct(int(f["foreign"]))
                self._json({"ok": True})
            elif p == "/api/adopt":
                engine.job_adopt(iran_id=int(f["iran"]), foreign_id=int(f["foreign"]))
                self._json({"ok": True})
            elif p == "/api/replace-foreign":
                engine.job_replace_foreign(int(f["service"]), int(f["foreign"]))
                self._json({"ok": True})
            elif p == "/api/replace-direct":
                engine.job_replace_direct(int(f["service"]), int(f["foreign"]))
                self._json({"ok": True})
            elif p == "/api/replace-iran":
                engine.job_replace_iran(int(f["service"]), int(f["iran"]))
                self._json({"ok": True})
            elif p == "/api/user-add":
                if not f.get("username") or not f.get("password"):
                    return self._json({"err": "username and password are required"})
                engine.add_user(int(f["service"]), f["username"].strip(), f["password"].strip(),
                                f.get("days", 0), f.get("gb", 0), f.get("conns", 0))
                self._json({"ok": True})
            elif p == "/api/user-act":
                with engine.STATE_LOCK:   # keep the sync out until the change is on the server
                    u = q("SELECT * FROM users WHERE id=?", (f["id"],), one=True)
                    if u:
                        if f["action"] == "del":
                            x("DELETE FROM users WHERE id=?", (u["id"],))
                        elif f["action"] == "toggle":
                            x("UPDATE users SET enabled=? WHERE id=?", (0 if u["enabled"] else 1, u["id"]))
                        elif f["action"] == "reset":
                            x("UPDATE users SET used_bytes=0 WHERE id=?", (u["id"],))
                        svc = q("SELECT * FROM services WHERE id=?", (u["service_id"],), one=True)
                        if svc:
                            iran = q("SELECT * FROM servers WHERE id=?", (svc["iran_id"],), one=True)
                            try:
                                engine.push_users(iran, svc["id"])
                            except Exception as e:
                                return self._json({"err": "saved locally but the server did not accept it: %s" % e})
                self._json({"ok": True})
            elif p == "/api/refresh":
                engine.refresh_service(int(f["service"]))
                self._json({"ok": True})
            else:
                self._json({"err": "unknown"}, 404)
        except Exception as e:
            self._json({"err": "%s: %s" % (type(e).__name__, e)})

    def log_message(self, *a):
        pass


def state():
    servers = q("SELECT * FROM servers ORDER BY role,ip")
    services = []
    for s in q("SELECT * FROM services ORDER BY id DESC"):
        iran = q("SELECT * FROM servers WHERE id=?", (s["iran_id"],), one=True) or {}
        fgn = q("SELECT * FROM servers WHERE id=?", (s["foreign_id"],), one=True) or {}
        us = q("SELECT * FROM users WHERE service_id=?", (s["id"],))
        tot = sum(float(u["used_bytes"] or 0) for u in us)
        last = q("SELECT live_conns FROM usage_log WHERE service_id=? ORDER BY id DESC LIMIT 1",
                 (s["id"],), one=True)
        services.append(dict(s, iran_ip=iran.get("ip"), foreign_ip=fgn.get("ip"),
                             user_count=len(us), total_h=fmt_bytes(tot),
                             live=(last or {}).get("live_conns", 0),
                             panel_user=iran.get("panel_user"), panel_pass=iran.get("panel_pass"),
                             l2tp_psk=iran.get("l2tp_psk"),
                             panel=("https://%s:%s/" % (iran.get("ip"), iran.get("panel_port") or 2098))
                                   if iran.get("panel_port") else "",
                             kind=(s.get("kind") or "vpn"), panel_url=s.get("panel_url")))
    users = []
    for u in q("SELECT u.*, s.name AS service_name FROM users u LEFT JOIN services s ON s.id=u.service_id"
               " ORDER BY u.service_id, u.username"):
        users.append(dict(u, used_h=fmt_bytes(u["used_bytes"]), days_left=days_left(u["expire"])))
    pts = q("SELECT ts, SUM(total_bytes) v FROM usage_log GROUP BY ts ORDER BY ts LIMIT 500")
    chart = [{"ts": p["ts"][5:16].replace("T", " "), "v": float(p["v"] or 0)} for p in pts]
    total_all = sum(float(u["used_bytes"] or 0) for u in q("SELECT used_bytes FROM users"))
    live_all = sum(s.get("live", 0) or 0 for s in services)
    return {
        "servers": servers, "services": services, "users": users,
        "chart": chart, "chart_max_h": fmt_bytes(max([p["v"] for p in chart], default=0)),
        "events": q("SELECT * FROM events ORDER BY id DESC LIMIT 12"),
        "key_cmd": core.key_install_command(),
        "sync": dict(SYNC), "version": VERSION,
        "kpi": {"servers": len(servers), "services": len(services),
                "users": len(users), "total_h": fmt_bytes(total_all), "live": live_all},
    }


SYNC = {"ts": None, "ok": False, "msg": "starting..."}


def auto_refresh_loop():
    """Keep this copy in step with the servers.

    The server holds the real account list, so two operators on two PCs (each
    with their own fleet.db) only agree if both keep pulling from it. Sync runs
    every 15s - add or change a user anywhere and it appears here on its own,
    with nobody pressing refresh. A heavier snapshot for the graph is taken
    every 5 minutes so the usage history doesn't get flooded.
    """
    last_snapshot = 0
    while True:
        try:
            services = q("SELECT id FROM services")
            snapshot = (time.time() - last_snapshot) > 300
            okc = 0
            for s in services:
                try:
                    svc = q("SELECT * FROM services WHERE id=?", (s["id"],), one=True)
                    if (svc.get("kind") or "vpn") == "v2ray":
                        # Marzban owns the accounts for these; mirror them the same way
                        fgn = q("SELECT * FROM servers WHERE id=?", (svc["foreign_id"],), one=True)
                        if fgn:
                            v2ray.pull_users(fgn, s["id"])
                            okc += 1
                        continue
                    iran = q("SELECT * FROM servers WHERE id=?", (svc["iran_id"],), one=True)
                    if iran:
                        engine.pull_users(iran, s["id"], log_usage=snapshot)
                        okc += 1
                except Exception:
                    pass
            if snapshot:
                last_snapshot = time.time()
            SYNC.update(ts=now(), ok=(okc == len(services) and len(services) > 0),
                        msg=("synced with %d/%d server(s)" % (okc, len(services))) if services
                            else "no service yet")
        except Exception as e:
            SYNC.update(ts=now(), ok=False, msg="sync problem: %s" % e)
        time.sleep(15)


def already_running():
    """True if our app already holds the port - then we just open the browser
    again instead of starting a second copy with a second database.

    Deliberately a raw socket, NOT urllib: Windows proxy settings (the user's own
    VPN app sets one) would send even a 127.0.0.1 request through the proxy and
    make this always look 'not running'.
    """
    return running_version() is not None


def running_version():
    """Version string of a Fleet Manager already holding the port, else None.

    Deliberately a raw socket, NOT urllib: Windows proxy settings (the user's own
    VPN app sets one) would send even a 127.0.0.1 request through the proxy and
    make this always report 'nothing running'.
    """
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect(("127.0.0.1", PORT))
        s.sendall(b"GET /api/ping HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        data = b""
        while len(data) < 4096:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"fleet-manager" in data:
                break
        if b"fleet-manager" not in data:
            return None
        tail = data.split(b"fleet-manager", 1)[1].strip().decode("ascii", "ignore")
        return tail.split()[0] if tail else "0"   # pre-1.3 builds sent no version
    except Exception:
        return None
    finally:
        s.close()


def ask_old_copy_to_quit():
    """An older build left running in the background (it has no window) would
    otherwise swallow every launch of the new one - the operator double-clicks the
    new exe and just gets the OLD app's page back. Tell it to exit and take over."""
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect(("127.0.0.1", PORT))
        s.sendall(b"GET /api/quit HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        s.recv(256)
    except Exception:
        pass
    finally:
        s.close()
    for _ in range(12):          # wait for the port to come free
        time.sleep(0.5)
        if running_version() is None:
            return True
    # Builds before 1.3 have no /api/quit, so they ignore the polite request and
    # would keep swallowing every launch of the new exe. Close the process that
    # owns the port instead - targeted by PID, never by image name, so this copy
    # (and its bootloader parent) can't kill itself.
    return _kill_port_owner()


def _kill_port_owner():
    try:
        mine = {str(os.getpid()), str(os.getppid())}
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                             creationflags=0x08000000).stdout
        pids = set()
        for ln in out.splitlines():
            parts = ln.split()
            if len(parts) >= 5 and parts[0] == "TCP" and parts[1].endswith(":%d" % PORT) \
               and parts[3].upper() == "LISTENING":
                pids.add(parts[4])
        for pid in pids - mine:
            subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True,
                           creationflags=0x08000000)
        for _ in range(16):
            time.sleep(0.5)
            if running_version() is None:
                return True
    except Exception:
        pass
    return False


def seed_db_if_first_run():
    """Ship the known servers/services/users inside the exe: on the very first
    run (no fleet.db yet) copy the bundled seed so the app opens ready to use."""
    if os.path.exists(core.DB_PATH):
        return False
    seed = os.path.join(getattr(sys, "_MEIPASS", APP_DIR_LOCAL), "assets", "seed.db")
    if os.path.exists(seed):
        try:
            import shutil
            shutil.copy(seed, core.DB_PATH)
            return True
        except Exception:
            pass
    return False


APP_DIR_LOCAL = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))


def main():
    url = "http://127.0.0.1:%d/" % PORT
    other = running_version()
    if other is not None:
        if other == VERSION:
            webbrowser.open(url)          # same build already up - just show it
            return
        # an older (or different) build is squatting the port; retire it so the
        # operator actually gets the exe they just double-clicked
        if not ask_old_copy_to_quit():
            _fatal("An older Fleet Manager (version %s) is still running and will not close.\n"
                   "Open Task Manager, end 'FleetManager.exe', then start this one again." % other)
            return
    seeded = seed_db_if_first_run()
    core.init_db()
    core.ensure_key()
    if seeded:
        core.log_event("app", "first run - loaded the bundled server list")
    try:
        srv = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Handler)
    except OSError:
        # lost the race with another copy starting at the same moment, or the
        # port belongs to some other program
        if already_running():
            webbrowser.open(url)
            return
        _fatal("Port %d is busy on this PC. Close whatever is using it and start again." % PORT)
        return
    srv.daemon_threads = True
    threading.Thread(target=auto_refresh_loop, daemon=True).start()
    print("Fleet Manager running at " + url)
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def _fatal(msg):
    try:
        with open(os.path.join(APP_DIR_LOCAL, "error.log"), "a") as f:
            f.write("%s  %s\n" % (datetime.datetime.now().isoformat(timespec="seconds"), msg))
    except Exception:
        pass
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, msg, "Fleet Manager", 0x10)
    except Exception:
        print(msg)


if __name__ == "__main__":
    main()
