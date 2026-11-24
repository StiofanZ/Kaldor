"""Exercise the embedded management page with local headless Chromium."""
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
import time

panel = (Path(__file__).resolve().parents[1] / "panel.html").read_text()
mock = """<script>
let snapshot={total:1,active:[],recent:[{time:1,device:'abc',target:'example.test',port:443,ingress:'HTTP',transport:'TCP',outbound:'direct',result:'opened'}]};
snapshot.active=[['client',snapshot.recent[0]]];
let saved,action,releasePhase="current";
let config={default:'east',devices:[],upstreams:['east','west'].map(name=>({
 name,protocol:'anytls',server:name+'.test:443'})),rules:[{port:443,outbound:'east'},{network:'udp',outbound:'reject'}]};
window.fetch=async (url,opts)=>{
 if(url.endsWith('page.cgi'))return new Response('<section id="release" data-installed="COMPONENT_VERSION" data-phase="'+releasePhase+'" data-version="0.4.0"></section><div id="activity-data">'+JSON.stringify(snapshot)+'</div>');
 if(url.endsWith('save.cgi')){const body=JSON.parse(opts.body);
 if(body.component_action){action=body;releasePhase=body.component_action==='check'?'available':'done';}else saved=body;
 return new Response('{"ok":true}');}
 if(url.endsWith('status.cgi'))return new Response('running');
 return new Response(JSON.stringify(config));
};
</script>"""
scenario = """<script>
addEventListener('load',async ()=>{
 try {
  const assert=(ok,msg)=>{if(!ok)throw Error(msg);};
  for(let i=0;document.querySelector('#parameters').inert && i<100;i++)
   await new Promise(resolve=>setTimeout(resolve,10));
  assert(!document.querySelector('#parameters').inert,'load: '+document.querySelector('#result').textContent);
  const form=document.getElementById('settings');
  const tab=id=>document.getElementById('tab-'+id);
  const active=id=>tab(id).getAttribute('aria-selected')==='true' &&
   document.querySelectorAll('[role=tabpanel]:not([hidden])').length===1 &&
   document.getElementById(tab(id).getAttribute('aria-controls')).getClientRects().length>0;
  assert(active('general'),'initial tab');
  tab('general').dispatchEvent(new KeyboardEvent('keydown',{key:'End'}));
  assert(active('access') && document.activeElement===tab('access') && form.hidden,'keyboard navigation');
  tab('access').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowRight'}));
  assert(active('general') && !form.hidden,'keyboard wrap');
  const port=document.querySelector('#listenPort');
  assert(port.labels[0].textContent.trim()==='代理端口','port label');
  assert(document.documentElement.scrollWidth<=innerWidth,'horizontal overflow');
  assert(port.value==='6000','default listen port');
  port.value='65536';assert(!port.checkValidity(),'port upper bound');
  tab('nodes').click();form.requestSubmit();
  assert(active('general') && document.activeElement===port && !saved,'hidden invalid port');
  port.value='16000';tab('nodes').click();
  assert(active('nodes'),'nodes tab');
  const [east,west]=document.querySelectorAll('#nodes fieldset');
  const fallback=document.querySelector('#fallback');
  const rule=document.querySelector('[data-key=outbound]');
  const name=east.querySelector('[data-key=name]');
  const click=(box,label)=>Array.from(box.querySelectorAll('button')).find(b=>b.textContent===label).click();
  name.value='west';name.dispatchEvent(new Event('input'));
  name.value='renamed';name.dispatchEvent(new Event('input'));
  assert(rule.value===east.id && fallback.value===east.id,'rename lost a selection');
  assert(rule.selectedOptions[0].textContent==='renamed','label did not follow rename');
  assert(byId('outboundMode').value==='rules' && byId('globalField').hidden,'legacy mode');
  click(west,'用于全局代理');
  assert(!saved && byId('globalOutbound').value===west.id && !byId('globalField').hidden && fallback.value===east.id && rule.value===east.id,'staging the switch');
  click(east,'删除');click(west,'删除');
  assert(east.isConnected&&west.isConnected,'deleted referenced node');
  tab('rules').click();assert(active('rules'),'rules tab');
  const [first,second]=document.querySelectorAll('#rules fieldset');
  const protocol=row=>row.querySelector('[data-key=network]');
  assert(protocol(first).value==='' && protocol(second).value==='udp','load rule transport');
  click(first,'下移');assert(first.previousElementSibling===second,'move down');
  click(first,'上移');assert(first.nextElementSibling===second,'move up');
  const suffix=first.querySelector('[data-key=domain_suffix]');
  suffix.value='.';assert(!suffix.checkValidity(),'invalid suffix accepted');
  tab('general').click();form.requestSubmit();
  assert(!saved && active('rules') && document.activeElement===suffix,'hidden invalid rule');
  suffix.value='example.org.';assert(suffix.checkValidity(),'absolute domain rejected');
  protocol(second).value='tcp';click(second,'上移');
  document.querySelector('#settings').requestSubmit();
  await new Promise(resolve=>setTimeout(resolve,10));
  for(let i=0;byId('result').textContent!=='已应用' && i<100;i++)await new Promise(r=>setTimeout(r,10));
  assert(byId('result').textContent==='已应用','initial save did not finish');
  assert(saved.listen_port===16000,'listen port missing from save');
  assert(saved.outbound_mode==='global' && saved.global_outbound==='west' && saved.default==='renamed' && !('devices' in saved) && saved.rules[1].outbound==='renamed' && !('network' in saved.rules[1]) && saved.rules[0].network==='tcp' && saved.rules[0].outbound==='reject','wrong saved routing');
  assert(saved.upstreams[0].previous_name==='east' && !saved.upstreams[0].secret,'credential edit');
  byId('outboundMode').value='global';byId('outboundMode').dispatchEvent(new Event('change'));
  byId('globalOutbound').value='';const beforeModeEdit=saved;form.requestSubmit();
  assert(saved===beforeModeEdit && byId('result').textContent.includes('选择节点或策略'),'empty global allowed');
  byId('outboundMode').value='direct';byId('outboundMode').dispatchEvent(new Event('change'));
  form.requestSubmit();
  for(let i=0;byId('result').textContent!=='已应用' && i<100;i++)await new Promise(r=>setTimeout(r,10));
  assert(saved.outbound_mode==='direct' && saved.rules.length===2 && !('devices' in saved),'direct mode save');
  tab('policies').click();document.getElementById('newPolicy').click();
  const group=byId('policies').firstElementChild, key=k=>group.querySelector('[data-key='+k+']');
  key('name').value='office';key('name').dispatchEvent(new Event('input'));
  const members=[...group.querySelectorAll('.member-list input')];
  members.forEach(m=>m.click());key('selected').value=members[1].value;
  fallback.value=group.id;byId('rules').querySelector('[data-key=outbound]').value=group.id;
  const renamed=byId(members[1].value).querySelector('[data-key=name]');
  renamed.value='backup';renamed.dispatchEvent(new Event('input'));
  click(byId(members[1].value),'删除');click(group,'删除');
  assert(group.isConnected && renamed.isConnected,'policy reference protection');
  key('name').value='proxy';key('name').dispatchEvent(new Event('input'));
  assert(fallback.value===group.id && group.isConnected,'policy option missing before save');
  byId('result').textContent='';form.requestSubmit();
  for(let i=0;byId('result').textContent!=='已应用' && i<100;i++)await new Promise(r=>setTimeout(r,10));
  assert(saved.default==='proxy' && saved.rules[0].outbound==='proxy','policy rename lost route');
  assert(saved.policies[0].selected==='backup' && saved.policies[0].members.join(',')==='east,backup','policy member rename');
  config=saved;await load();
  for(const kind of ['auto','load_balance']){
   const row=byId('policies').firstElementChild, mode=row.querySelector('[data-key=type]');
   mode.value=kind;mode.dispatchEvent(new Event('change'));
   assert(row.querySelector('[data-key=selected]').disabled,'manual field enabled');
   form.requestSubmit();await new Promise(resolve=>setTimeout(resolve,20));
   assert(saved.policies[0].type===kind && !('selected' in saved.policies[0]),'policy type save');
  }
  tab('rules').click();
  assert(!byId('rulePanel').querySelector('input[type=file]'),'unexpected local file picker');
  const count=saved.rules.length;
  saved.rules.push({standard:'DOMAIN,first.example',outbound:'direct'});
  config=saved;await load();
  byId('newStandard').click();
  const expression=byId('rules').lastElementChild.querySelector('[data-key=standard]');
  expression.value='DST-PORT,443,REJECT';expression.dispatchEvent(new Event('change'));
  click(byId('rulePanel'),'添加远程规则');
  const remote=byId('rules').lastElementChild;
  const download=remote.querySelector('[data-key=download_outbound]');
  assert(download.value==='direct' && ![...download.options].some(o=>o.value==='reject'),'invalid download choices');
  download.value=byId('policies').firstElementChild.id;
  remote.querySelector('[data-key=outbound]').value='reject';
  remote.querySelector('[data-key=rule_url]').value='https://rules.example/remote.list';
  form.requestSubmit();await new Promise(r=>setTimeout(r,20));
  assert(saved.rules[count].standard==='DOMAIN,first.example' && saved.rules[count].outbound==='direct' && saved.rules[count+1].standard==='DST-PORT,443' && saved.rules[count+1].outbound==='reject' && saved.rules.at(-1).rule_url.endsWith('/remote.list'),'existing, manual and remote rules round trip');
  assert(saved.rules.at(-1).download_outbound==='proxy' && saved.rules.at(-1).outbound==='reject','download outlet mixed with traffic outlet');
  saved.rules.at(-1).rule_digest='a'.repeat(64);config=saved;await load();
  assert(rows('rules').at(-1).rule_digest==='a'.repeat(64),'lost cached revision on reload');
  const refreshed=byId('rules').lastElementChild.querySelector('[data-key=download_outbound]');
  refreshed.value='direct';assert(!rows('rules').at(-1).rule_digest,'changed outlet reused cached download');
  refreshed.value=byId('policies').firstElementChild.id;
  click(byId('rules').lastElementChild,'重新下载');assert(!rows('rules').at(-1).rule_digest,'refresh did not request download');
  tab('dns').click();assert(active('dns') && byId('dnsFallback').value==='', 'legacy DNS fallback');
  byId('newDnsRule').click();
  const dnsBox=byId('dnsRules').firstElementChild;
  dnsBox.querySelector('[data-key=value]').value='example.org';
  const dnsNode=byId('nodes').firstElementChild;
  dnsBox.querySelector('[data-key=outbound]').value=dnsNode.id;
  byId('dnsFallback').value='@rules';byId('directResolver').value='alidns';
  byId('result').textContent='';form.requestSubmit();await new Promise(r=>setTimeout(r,20));
  assert(saved.dns.direct_resolver==='alidns' && saved.dns.default==='@rules' && saved.dns.rules[0].type==='suffix' && saved.dns.rules[0].outbound===dnsNode.querySelector('[data-key=name]').value,'DNS save');
  config=saved;await load();assert(byId('directResolver').value==='alidns' && rows('dnsRules')[0].value==='example.org' && byId('dnsFallback').value==='@rules','DNS reload');
  for(const id of ['connections','access']){
   tab(id).click();await new Promise(resolve=>setTimeout(resolve,20));
   assert(active(id) && form.hidden && byId(id).innerText.includes('example.test:443'),'activity '+id);
  }
  snapshot=null;byId('access').querySelector('button').click();await new Promise(resolve=>setTimeout(resolve,20));
  assert(byId('access').innerText.includes('暂无运行数据') && !byId('access').innerText.includes('example.test'),'unavailable snapshot');
  tab('general').click();assert(active('general') && !byId('release').hidden,'update within general');
  const check=document.getElementById('checkRelease'),install=document.getElementById('installRelease');
  await check.onclick();assert(action.component_action==='check'&&!install.hidden,'release check');
  window.confirm=()=>false;await install.onclick();assert(action.component_action==='check','cancelled upgrade');
  window.confirm=()=>true;await install.onclick();
  assert(action.component_action==='upgrade'&&action.version==='0.4.0'&&install.hidden,'selected release upgrade');
  assert(document.getElementById('releaseResult').textContent.includes('已完成'),'upgrade result');
  navigator.sendBeacon('/result','PASS');
 } catch(err){navigator.sendBeacon('/result',String(err));}
});
</script>"""
# Model the same-origin frame shipped in the firmware, including its initial height.
embedded = """<script>
addEventListener('load', async ()=>{
 const frame=document.querySelector('iframe'), child=frame.contentDocument;
 const assert=(ok,msg)=>{if(!ok)throw Error(msg);};
 const fitted=async ()=>{
  for(let i=0;i<100;i++){
   const height=Math.ceil(child.body.getBoundingClientRect().height);
   if(Math.abs(frame.clientHeight-height)<=1 && child.scrollingElement.scrollHeight<=frame.clientHeight+1)
    return frame.clientHeight;
   await new Promise(resolve=>setTimeout(resolve,10));
  }
  throw Error('frame '+frame.clientHeight+' body '+child.body.getBoundingClientRect().height);
 };
 try{
  const short=await fitted();
  assert(short<700,'frame did not shrink on load');
  child.getElementById('tab-rules').click();
  for(let i=0;i<6;i++)child.getElementById('newRule').click();
  const tall=await fitted();
  assert(tall>innerHeight && tall>short,'long list did not expand');
  scrollTo(0,document.scrollingElement.scrollHeight);
  assert(scrollY>0 && frame.contentWindow.scrollY===0,'scroll owner');
  child.getElementById('rules').lastElementChild.querySelector('.row-tools button:last-child').click();
  assert(await fitted()<tall,'deleting a row did not shrink frame');
  child.getElementById('tab-access').click();
  assert(await fitted()<short && child.scrollingElement.scrollWidth<=frame.clientWidth,'short tab size');
  navigator.sendBeacon('/result','PASS');
 }catch(err){navigator.sendBeacon('/result',String(err));}
});
</script>"""
class TestPage(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(self.server.page.encode())

    def do_POST(self):
        if self.path != "/result":
            self.send_error(404)
            return
        self.server.result = self.rfile.read(int(self.headers["Content-Length"])).decode()
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


with tempfile.TemporaryDirectory() as directory, ThreadingHTTPServer(("127.0.0.1", 0), TestPage) as server:
    view = panel.replace("<script>", mock + "<script>", 1)
    pages = {
        "standalone": view.replace("</html>", scenario + "</html>"),
        "embedded": ('<!doctype html><meta charset="utf-8"><iframe style="display:block;width:98%;'
                     'height:700px;border:0" srcdoc="' + escape(view, quote=True) + '"></iframe>' + embedded),
    }
    server.timeout = 1
    for mode, html in pages.items():
        server.page = html
        for width in (760, 390):
            server.result = None
            browser = subprocess.Popen([
                sys.argv[1], f"--window-size={width},700", "--headless", "--disable-gpu",
                "--disable-background-networking", "--disable-extensions", "--no-first-run", "--disable-sync",
                "--user-data-dir=" + str(Path(directory) / f"{mode}-{width}"),
                f"http://127.0.0.1:{server.server_port}/",
            ])
            try:
                deadline = time.monotonic() + 20
                while server.result is None and time.monotonic() < deadline and browser.poll() is None:
                    server.handle_request()
                if server.result != "PASS":
                    sys.exit(f"{mode} {width}: {server.result or 'browser timeout'}")
                print(f"{mode} {width} PASS", flush=True)
            finally:
                browser.terminate()
                browser.wait(timeout=10)
