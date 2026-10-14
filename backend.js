(()=>{
const cfg=window.SENTRIX_CONFIG||{},ok=cfg.url&&cfg.key&&!/^YOUR_/.test(cfg.url)&&window.supabase;
const sb=ok?supabase.createClient(cfg.url,cfg.key):null;
let user=null,mode='in',last=null,saving=false;
const TY={'Social Profile':'social','Website / URL':'url','Mobile Application':'app'},UI={social:'Social',url:'URL',app:'App'};
const SEV=s=>s>=75?'Critical':s>=55?'High':s>=35?'Medium':'Low',LV=s=>s>=70?'high':s>=40?'medium':'low';
const SU={new:'New',investigating:'Investigating',resolved:'Resolved',dismissed:'Dismissed'},ST0=[...ST];
const REC=['Compare against the official asset manually','Collect screenshots and URLs as evidence','Have an analyst review before any report or takedown request'];
const msg=e=>{const m=((e&&e.message)||'').toLowerCase();return m.includes('invalid login')?'Email or password is incorrect.':m.includes('already')?'That email is already registered. Try signing in.':m.includes('not confirmed')||m.includes('confirm')?'Confirm your email first. Check your inbox.':m.includes('rate')?'Too many attempts. Wait a minute and try again.':m.includes('fetch')||m.includes('network')?'Network problem. Check your connection and try again.':m.includes('password')?'Password must be at least 8 characters.':'Something went wrong. Please try again.'};
// auth dialog
document.body.insertAdjacentHTML('beforeend',`<dialog id="ad" style="background:var(--s1);color:var(--tx);border:1px solid var(--ln);border-radius:14px;max-width:380px;width:92%;padding:24px"><form id="af" method="dialog" novalidate><h3 id="at"></h3><p id="ae" class="sm" style="color:var(--cr);min-height:20px" role="alert"></p><div id="an2"><label class="sm mu" for="ax">Display name</label><input id="ax" maxlength="60"></div><div id="aem"><label class="sm mu" for="ay">Email</label><input id="ay" type="email" autocomplete="email"></div><div id="apw"><label class="sm mu" for="az">Password</label><input id="az" type="password" minlength="8" autocomplete="current-password"></div><div class="row" style="margin-top:14px"><button class="btn p" id="ab" type="submit"></button><button class="btn" type="button" id="ac">Close</button></div><p class="sm"><a href="#" id="s1"></a> · <a href="#" id="s2"></a></p></form></dialog>`);
const D=document.getElementById('ad');
function view(m){mode=m;$('#ae').textContent='';$('#at').textContent={in:'Sign in',up:'Create account',fg:'Reset password',nw:'Choose a new password'}[m];$('#ab').textContent={in:'Sign in',up:'Sign up',fg:'Send reset link',nw:'Save password'}[m];
$('#an2').classList.toggle('hide',m!='up');$('#aem').classList.toggle('hide',m=='nw');$('#apw').classList.toggle('hide',m=='fg');
$('#s1').textContent=m=='in'?'Create account':'Sign in';$('#s1').onclick=e=>{e.preventDefault();view(m=='in'?'up':'in')};$('#s2').textContent='Forgot password?';$('#s2').onclick=e=>{e.preventDefault();view('fg')};$('#s2').classList.toggle('hide',m=='nw')}
$('#ac').onclick=()=>D.close();
$('#af').onsubmit=async e=>{e.preventDefault();const em=$('#ay').value.trim(),pw=$('#az').value,b=$('#ab'),er=$('#ae');er.textContent='';
if(mode!='nw'&&!/^\S+@\S+\.\S+$/.test(em))return er.textContent='Enter a valid email address.';
if((mode=='in'||mode=='up'||mode=='nw')&&pw.length<8)return er.textContent='Password must be at least 8 characters.';
b.disabled=true;let r;
try{if(mode=='in')r=await sb.auth.signInWithPassword({email:em,password:pw});
else if(mode=='up'){r=await sb.auth.signUp({email:em,password:pw,options:{emailRedirectTo:location.origin,data:{display_name:$('#ax').value.trim()}}});if(!r.error&&!r.data.session){D.close();toast('Check your email to confirm your account, then sign in.');b.disabled=false;return}}
else if(mode=='fg'){r=await sb.auth.resetPasswordForEmail(em,{redirectTo:location.origin});if(!r.error){D.close();toast('If that email exists, a reset link is on its way.');b.disabled=false;return}}
else r=await sb.auth.updateUser({password:pw});
}catch(x){r={error:x}}
b.disabled=false;if(r.error)return er.textContent=msg(r.error);D.close();toast(mode=='nw'?'Password updated':'Signed in');};
const sl=[...document.querySelectorAll('nav .links a')].find(a=>a.textContent=='Sign In');
sl.onclick=async e=>{e.preventDefault();$('#nl').classList.remove('o');if(!sb)return toast('Backend not configured yet. Follow README step 3.');if(user){await sb.auth.signOut();return toast('Signed out')}view('in');D.showModal()};
// ---- real backend scanner (all analysis happens on the server) ----
const API=(cfg.apiUrl||'').replace(/\/$/,'');
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cap=s=>s?s[0].toUpperCase()+s.slice(1):'';
const PS={match:'Checked: match found',no_match:'Checked: no match returned (not proof of safety)',no_report:'Checked: no existing report',unavailable:'Unavailable',failed:'Failed',pending:'Pending'};
async function api(path,o={}){const{data}=await sb.auth.getSession(),tk=data.session&&data.session.access_token;
if(!tk)throw new Error('Sign in to run and save scans.');let r;
try{r=await fetch(API+path,{...o,headers:{'content-type':'application/json',authorization:'Bearer '+tk}})}catch{throw new Error('Cannot reach the backend. Check that it is running and apiUrl in config.js is correct.')}
const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||'Request failed.');return j}
document.getElementById('q').insertAdjacentHTML('afterend','<label class="sm mu" for="ex1" style="display:block;margin-top:10px">Optional details: profile bio, publisher, package ID, store URL or file SHA-256</label><textarea id="ex1" maxlength="300"></textarea>');
$('#sf').addEventListener('submit',async e=>{e.preventDefault();e.stopImmediatePropagation();
const v=$('#q').value.trim(),er=$('#er'),go=$('#go');er.textContent='';
if(v.length<3){er.textContent='Enter at least 3 characters: a profile URL, app name, or URL.';return}
if(!sb||!user){er.textContent=sb?'Sign in first. Real scans are saved to your private history.':'Backend not configured yet. See the README.';return}
const li=$$('#st li');li.forEach(x=>x.className='');let i=0;const tm=setInterval(()=>{if(i>0)li[i-1].className='done';if(i<3){li[i].className='on';i++}},900);
go.disabled=true;go.textContent='Analyzing…';$('#out').innerHTML='<span class="mu">Querying configured providers…</span>';
try{const sc=await api('/api/scans',{method:'POST',body:JSON.stringify({assetType:document.querySelector('[name=t]:checked').value=='Social Profile'?'social':document.querySelector('[name=t]:checked').value=='Mobile Application'?'app':'url',value:v,brand:$('#br').value,details:$('#ex1').value})});
clearInterval(tm);li.forEach(x=>x.className='done');render(sc);toast('Scan saved to your history');load()}
catch(x){clearInterval(tm);li.forEach(y=>y.className='');$('#out').innerHTML='';er.textContent=x.message}
go.disabled=false;go.textContent='Analyze Threat'},true);
function render(sc){const L=cap(sc.risk_level),a=sc.analysis||{};
$('#out').innerHTML=`${sc.limited?'<p class="sm" style="border:1px solid var(--me);border-radius:10px;padding:10px"><b>Limited assessment:</b> no provider completed a check, so this score reflects text heuristics only.</p>':''}<div class="score" style="color:${SC[L]}">${sc.risk_score}<span class="sm mu">/100</span></div><p><span class="sev ${L}">${L} risk</span></p><p class="sm">${esc(sc.summary)}</p>
<b class="sm">Provider checks (facts)</b><div class="tw"><table class="sm">${(sc.evidence||[]).map(p=>`<tr><td>${esc(p.provider)}</td><td>${PS[p.status]||esc(p.status)}${p.error?': '+esc(p.error):''}</td><td class="mu">${esc((p.evidence||[]).join('; '))}</td></tr>`).join('')||'<tr><td class="mu">No provider was applicable to this input.</td></tr>'}</table></div>
<b class="sm">Indicators</b><ul class="sm">${sc.indicators.map(i=>`<li>${esc(i.text)} <span class="demo">${esc(i.source)}</span></li>`).join('')||'<li class="mu">None found.</li>'}</ul>
<b class="sm">How the score was set</b><ul class="sm mu">${(a.basis||[]).map(x=>`<li>${esc(x)}</li>`).join('')}</ul>
<b class="sm">AI interpretation (not provider fact)</b>${a.available?`<p class="sm">${esc(a.summary)}</p><p class="sm mu">${esc(a.explanation)}</p><p class="sm mu">Confidence: ${esc(a.confidence)}</p>`:`<p class="sm mu">${esc(a.reason||'Unavailable.')}</p>`}
<b class="sm">Recommended next steps</b><ul class="sm mu">${sc.recommendations.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>
<b class="sm">Limitations</b><ul class="sm mu">${(a.limitations||[]).map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`}
// ---- workspace + KPIs from the API ----
const DEMO_T=T.slice();let rows=[];
async function load(){if(!user){T=DEMO_T;ST.splice(0,ST.length,...ST0);$('#dt').innerHTML='<p class="mu">Showing sample threats. Sign in to see your own scans.</p>';rt();return}
ST.splice(0,ST.length,...Object.values(SU));
try{rows=await api('/api/scans');const st=await api('/api/dashboard/stats');
T=rows.map(s=>({id:'S-'+s.id.slice(0,6),_id:s.id,_i:s.investigations[0],_s:s,n:s.asset_value,ty:UI[s.asset_type],s:cap(s.risk_level),sc:s.risk_score,ind:s.indicators.map(i=>i.text||i)}));
sel=null;$('#dt').innerHTML='<p class="mu">'+(T.length?'Select a scan to open it.':'No saved scans yet. Run the scanner above while signed in.')+'</p>';rt();
const c=[st.total,st.byLevel.high+st.byLevel.critical,st.byLevel.medium,st.openInvestigations],l=['Your scans','High or critical','Medium','New investigations'];
$$('.kpi').forEach((e,j)=>{e.querySelector('span').textContent=l[j];e.querySelector('b').textContent=c[j]})}catch(x){toast(x.message)}}
const od=window.det;window.det=function(){const t=T.find(x=>x.id==sel),live=user&&t&&t._i;
if(live)S[sel]={st:SU[t._i.status],notes:(t._i.notes||'').split('\n').filter(Boolean)};od();if(!live)return;
$('#ss').onchange=async e=>{const v=Object.keys(SU).find(k=>SU[k]==e.target.value);try{await api('/api/investigations/'+t._i.id,{method:'PATCH',body:JSON.stringify({status:v})});t._i.status=v;rt();toast('Status saved')}catch(x){toast(x.message)}};
$('#an').onclick=async()=>{const v=$('#nt').value.trim();if(!v)return toast('Write a note first.');try{const r=await api('/api/investigations/'+t._i.id+'/notes',{method:'POST',body:JSON.stringify({note:v})});t._i.notes=r.notes;det();toast('Note saved')}catch(x){toast(x.message)}};
$('#dt').insertAdjacentHTML('beforeend','<div class="row" style="margin-top:10px"><button class="btn" id="ex">Export JSON</button><button class="btn" id="ec">Export CSV (all)</button><button class="btn" id="dl">Delete scan</button></div>');
const dlf=(n,b,t)=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([b],{type:t}));a.download=n;a.click()};
$('#ex').onclick=()=>dlf('sentrix-'+t.id+'.json',JSON.stringify(t._s,null,2),'application/json');
$('#ec').onclick=()=>{const q=v=>'"'+String(v??'').replace(/"/g,'""').replace(/^[=+\-@]/,"'$&")+'"';dlf('sentrix-scans.csv',['id,asset,type,risk,level,status,created'].concat(rows.map(s=>[s.id,s.asset_value,s.asset_type,s.risk_score,s.risk_level,s.investigations[0]?.status,s.created_at].map(q).join(','))).join('\n'),'text/csv')};
$('#dl').onclick=async()=>{if(!confirm('Delete this scan and its investigation?'))return;try{await api('/api/scans/'+t._id,{method:'DELETE'});toast('Scan deleted');load()}catch(x){toast(x.message)}}};
if(sb)sb.auth.onAuthStateChange((ev,s)=>{user=s?s.user:null;sl.textContent=user?'Sign out':'Sign In';if(ev=='PASSWORD_RECOVERY'){view('nw');D.showModal()}setTimeout(load,0)});
})();
