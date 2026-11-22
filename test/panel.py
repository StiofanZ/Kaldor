"""Exercise the embedded management page with local headless Chromium."""
from pathlib import Path
import subprocess
import sys
import tempfile

panel = (Path(__file__).resolve().parents[1] / "panel.html").read_text()
mock = """<script>
let saved;
let config={default:'east',devices:[],upstreams:['east','west'].map(name=>({
 name,protocol:'anytls',server:name+'.test:443'})),rules:[{port:443,outbound:'east'},{network:'udp',outbound:'reject'}]};
window.fetch=async (url,opts)=>{
 if(url.endsWith('save.cgi')){saved=JSON.parse(opts.body);return new Response('{"ok":true}');}
 if(url.endsWith('status.cgi'))return new Response('running');
 return new Response(JSON.stringify(config));
};
</script>"""
scenario = """<script>
addEventListener('load',async ()=>{
 const result=document.createElement('pre');document.body.append(result);
 try {
  const assert=(ok,msg)=>{if(!ok)throw Error(msg);};
  for(let i=0;document.querySelector('#settings').inert && i<100;i++)
   await new Promise(resolve=>setTimeout(resolve,10));
  assert(!document.querySelector('#settings').inert,'load: '+document.querySelector('#result').textContent);
  const [east,west]=document.querySelectorAll('#nodes fieldset');
  const fallback=document.querySelector('#fallback');
  const rule=document.querySelector('[data-key=outbound]');
  const name=east.querySelector('[data-key=name]');
  const click=(box,label)=>Array.from(box.querySelectorAll('button')).find(b=>b.textContent===label).click();
  name.value='west';name.dispatchEvent(new Event('input'));
  name.value='renamed';name.dispatchEvent(new Event('input'));
  assert(rule.value===east.id && fallback.value===east.id,'rename lost a selection');
  assert(rule.selectedOptions[0].textContent==='renamed','label did not follow rename');
  click(west,'设为默认出口');
  assert(!saved && fallback.value===west.id && rule.value===east.id,'staging the switch');
  click(east,'删除');click(west,'删除');
  assert(east.isConnected&&west.isConnected,'deleted referenced node');
  const [first,second]=document.querySelectorAll('#rules fieldset');
  const protocol=row=>row.querySelector('[data-key=network]');
  assert(protocol(first).value==='' && protocol(second).value==='udp','load rule transport');
  click(first,'下移');assert(first.previousElementSibling===second,'move down');
  click(first,'上移');assert(first.nextElementSibling===second,'move up');
  const suffix=first.querySelector('[data-key=domain_suffix]');
  suffix.value='.';assert(!suffix.checkValidity(),'invalid suffix accepted');
  suffix.value='example.org.';assert(suffix.checkValidity(),'absolute domain rejected');
  protocol(second).value='tcp';click(second,'上移');
  document.querySelector('#settings').requestSubmit();
  await new Promise(resolve=>setTimeout(resolve,10));
  assert(saved.default==='west' && saved.rules[1].outbound==='renamed' && !('network' in saved.rules[1]) && saved.rules[0].network==='tcp' && saved.rules[0].outbound==='reject','wrong saved routing');
  assert(saved.upstreams[0].previous_name==='east' && !saved.upstreams[0].secret,'credential edit');
  result.textContent='PANEL_PASS';
 } catch(err){result.textContent='PANEL_FAIL '+err;}
});
</script>"""
with tempfile.TemporaryDirectory() as directory:
    page = Path(directory) / "panel.html"
    page.write_text(panel.replace("<script>", mock + "<script>", 1)
                    .replace("</html>", scenario + "</html>"))
    output = subprocess.check_output([
        sys.argv[1], "--headless", "--disable-gpu", "--disable-background-networking",
        "--disable-extensions", "--no-first-run", "--disable-sync",
        "--user-data-dir=" + str(Path(directory) / "profile"), "--dump-dom",
        "--virtual-time-budget=2000", page.as_uri()
    ], text=True, timeout=45)
    if "<pre>PANEL_PASS</pre>" not in output:
        sys.exit(output.rsplit("<pre>", 1)[-1][:240])
    print("Management page rename, reference protection and default switching, transport and rule ordering PASS")
