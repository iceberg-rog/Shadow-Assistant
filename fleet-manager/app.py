"""Fleet Manager - one .exe that provisions, migrates and monitors the VPN fleet.

Double-click it: a small local web app opens in your browser. Nothing is exposed
to the internet (it binds 127.0.0.1 only). All state lives in fleet.db beside
the exe, so accounts survive any server being replaced.
"""
import os, sys, json, time, threading, webbrowser, datetime, urllib.parse, http.server, socketserver, socket
import core, engine
from core import q, x, now, today

PORT_RANGE = range(8770, 8800)


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
<h1>Fleet Manager</h1>
<div class=sub>Provision, migrate and monitor your VPN servers &mdash; everything stored locally in <span class=mono>fleet.db</span></div>
<div class=tabs>
  <button data-t=dash class=on onclick=tab('dash')>Dashboard</button>
  <button data-t=servers onclick=tab('servers')>Servers</button>
  <button data-t=build onclick=tab('build')>New service</button>
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
  var v=document.getElementById('view');
  if(cur=='dash')v.innerHTML=dash();
  else if(cur=='servers')v.innerHTML=servers();
  else if(cur=='build')v.innerHTML=build();
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
     +(s.panel?'<a href="'+esc(s.panel)+'" target=_blank><button class=ghost>panel</button></a>':'')+'</td></tr>';
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
  var h='<div class=card><h2>Replace the FOREIGN server (exit got filtered)</h2><div class=row>'
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
load();setInterval(function(){if(cur=='dash')load();},15000);
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
        elif p == "/api/state":
            self._json(state())
        elif p == "/api/job":
            self._json(engine.jsnapshot())
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
            elif p == "/api/adopt":
                engine.job_adopt(iran_id=int(f["iran"]), foreign_id=int(f["foreign"]))
                self._json({"ok": True})
            elif p == "/api/replace-foreign":
                engine.job_replace_foreign(int(f["service"]), int(f["foreign"]))
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
                        except Exception:
                            pass
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
                             panel=("https://%s:%s/" % (iran.get("ip"), iran.get("panel_port") or 2098))
                                   if iran.get("panel_port") else ""))
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
        "kpi": {"servers": len(servers), "services": len(services),
                "users": len(users), "total_h": fmt_bytes(total_all), "live": live_all},
    }


def auto_refresh_loop():
    """Every 5 minutes pull usage from every live service so the graph grows
    even when the window is just sitting open."""
    while True:
        time.sleep(300)
        try:
            for s in q("SELECT id FROM services"):
                try:
                    engine.refresh_service(s["id"])
                except Exception:
                    pass
        except Exception:
            pass


def free_port():
    for p in PORT_RANGE:
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
            return p
        except Exception:
            continue
        finally:
            s.close()
    return 8799


def main():
    core.init_db()
    core.ensure_key()
    port = free_port()
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    threading.Thread(target=auto_refresh_loop, daemon=True).start()
    url = "http://127.0.0.1:%d/" % port
    print("Fleet Manager running at " + url)
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
