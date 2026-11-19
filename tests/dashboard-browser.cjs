const assert = require('node:assert/strict');
const {spawn,execFileSync} = require('node:child_process');
const {mkdtemp,writeFile,readFile,readdir,rm,mkdir} = require('node:fs/promises');
const {tmpdir} = require('node:os');
const {join,resolve} = require('node:path');
const {chromium} = require(process.env.PATRONUS_PLAYWRIGHT_MODULE || '../plugins/codex-api/tests/node_modules/playwright');
(async()=>{
 const root=await mkdtemp(join(tmpdir(),'patronus-dashboard-017-'));
 const binary=process.env.PATRONUS_TEST_SCANNER||resolve('target/debug/patronus-security-scanner');
 await writeFile(join(root,'config.toml'),'[provider]\nmode="local"\n[ark]\ncategories=["pii","dlp"]\nmax_level="l1"\ndownload_files=false\n');
 const event={schema:'patronus.protocol.event.v1',timestamp:'2026-11-13T12:00:00Z',host:'codex',session_id:'sha256:'+'a'.repeat(64),event:'scan_completed',direction:'response',tool_name:'read_file',status:'approved'};
 execFileSync(binary,['protocol','append','--journal-only'],{input:JSON.stringify(event),env:{...process.env,PATRONUS_DATA_DIR:root}});
 const journal=(await readdir(join(root,'protocol'))).find(name=>name.endsWith('.jsonl'));
 const snapshot=join(root,'protocol',journal.replace('.jsonl','.html'));
 await writeFile(snapshot,'existing authenticated activity view');
 const child=spawn(binary,['dashboard'],{env:{...process.env,PATRONUS_DATA_DIR:root},stdio:['ignore','pipe','pipe']});
 let browser;
 try{
  const url=await new Promise((ok,fail)=>{let text='';const timer=setTimeout(()=>fail(Error('dashboard did not start')),15000);child.stdout.on('data',c=>{text+=c;const m=text.match(/http:\/\/127\.0\.0\.1:\d+\//);if(m){clearTimeout(timer);ok(m[0]);}});child.on('error',fail);child.on('exit',c=>{if(c)fail(Error(`dashboard exited ${c}`));});});
  browser=await chromium.launch({headless:true,...(process.env.PATRONUS_BROWSER_EXECUTABLE?{executablePath:process.env.PATRONUS_BROWSER_EXECUTABLE}:{})});
  const page=await browser.newPage({viewport:{width:1440,height:1050}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
  // Host installation state is covered by the host suites; keep this browser test deterministic.
  await page.route('**/api/integrations',r=>r.fulfill({contentType:'application/json',body:'[]'}));
  let releaseActivity;const activityGate=new Promise(resolve=>{releaseActivity=resolve;});
  await page.route('**/api/activity',async route=>{await activityGate;await route.continue();});
  const stalled=require('node:net').connect(Number(new URL(url).port),'127.0.0.1');await new Promise(ok=>stalled.once('connect',ok));stalled.write('GET / HTTP/1.1\r\n');
  await page.goto(url);assert(!stalled.destroyed,'a partial request must not block other connections');stalled.destroy();
  assert.equal(await readFile(snapshot,'utf8'),'existing authenticated activity view','GET must not rewrite historical pages');await page.locator('#policy-host').waitFor({state:'attached'});await page.waitForFunction(()=>document.querySelector('#policy-list').children.length>0);
  assert.equal(await page.locator('.activity-content').getAttribute('aria-busy'),'true','settings must load while activity is blocked');
  releaseActivity();await page.waitForFunction(()=>!document.querySelector('.activity-content').hasAttribute('aria-busy'));
  if(process.env.PATRONUS_UI_OUTPUT){await mkdir(process.env.PATRONUS_UI_OUTPUT,{recursive:true});await page.screenshot({path:join(process.env.PATRONUS_UI_OUTPUT,'patronus-local-overview.png')});}
  await page.locator('label[for="tab-policies"]').click();await page.locator('#policy-host').selectOption('global');
  await page.locator('#pii-mode').selectOption('recall');await page.locator('#dlp-mode').selectOption('balanced');await page.locator('#policy-search').fill('pii_imei');await page.locator('#policy-list input[type=checkbox]').uncheck();await page.locator('#save-policies').click();await page.getByRole('status').filter({hasText:'Policies saved'}).waitFor();
  const persisted=await page.evaluate(async()=>{const token=document.querySelector('meta[name="patronus-token"]').content;return (await fetch('/api/state',{headers:{'X-Patronus-Token':token}})).json();});
  assert.equal(persisted.config.analysis.l1_rules.pii_imei,false);
  assert.deepEqual(persisted.config.plugin_policies,{},'saving CLI defaults must not freeze inherited plugin profiles');
  await page.reload();await page.waitForFunction(()=>document.querySelector('#policy-list').children.length>0);await page.locator('label[for="tab-policies"]').click();await page.locator('#policy-host').selectOption('global');assert.equal(await page.locator('#pii-mode').inputValue(),'recall');assert.equal(await page.locator('#dlp-mode').inputValue(),'balanced');
  await page.locator('#policy-host').selectOption('codex');await page.locator('#pii-mode').selectOption('strict');await page.locator('#save-policies').click();await page.getByRole('status').filter({hasText:'Policies saved'}).waitFor();
  await page.locator('#policy-search').fill('pii_aadhaar_in_context_free');await page.getByText('Requires scored mode — inactive in Strict',{exact:true}).waitFor();
  const output=process.env.PATRONUS_UI_OUTPUT;if(output){await mkdir(output,{recursive:true});await page.screenshot({path:join(output,'patronus-local-rules.png'),fullPage:true});}
  await page.locator('label[for="tab-shell"]').click();await page.locator('#shell-host').selectOption('claude');await page.locator('#shell-ask').selectOption('ask');await page.locator('#add-cedar').click();await page.locator('#save-shell').click();await page.getByRole('status').filter({hasText:'Cedar validated'}).waitFor();
  const source=page.locator('#cedar-editors textarea').first();await source.fill('invalid cedar');await page.locator('#save-shell').click();await page.locator('#control-message.error').waitFor();
  await page.reload();await page.waitForFunction(()=>document.querySelector('#policy-list').children.length>0);await page.locator('label[for="tab-shell"]').click();await page.locator('#shell-host').selectOption('claude');assert.equal(await page.locator('#shell-ask').inputValue(),'ask');assert.match(await page.locator('#cedar-editors textarea').first().inputValue(),/@decision\("block"\)/);
  if(output)await page.screenshot({path:join(output,'patronus-local-shell.png'),fullPage:true});
  for(const width of [390,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`overflow ${width}`);}
  await page.emulateMedia({colorScheme:'dark'});
  const contrast=await page.evaluate(()=>{const heading=document.querySelector('.shell-content .panel-head h2'),panel=heading.closest('.panel-head');const luminance=color=>{const rgb=color.match(/[\d.]+/g).slice(0,3).map(Number).map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;});return rgb[0]*.2126+rgb[1]*.7152+rgb[2]*.0722;};const a=luminance(getComputedStyle(heading).color),b=luminance(getComputedStyle(panel).backgroundColor);return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);});
  assert(contrast>=4.5,`dark-mode heading contrast ${contrast}`);if(output)await page.screenshot({path:join(output,'patronus-local-shell-dark.png'),fullPage:true});
  await page.unroute('**/api/activity');
  await page.route('**/api/activity',route=>route.fulfill({contentType:'text/html',body:'<input id="activity-search" type="search"><section class="panel"><div class="table-wrap"><table><tbody>'+Array.from({length:36},(_,i)=>`<tr><td>session-${String(i).padStart(2,'0')}</td></tr>`).join('')+'</tbody></table></div></section>'}));
  await page.reload();await page.locator('.activity-content .pagination').waitFor({state:'attached'});
  assert.equal(await page.locator('.activity-content tbody tr:visible').count(),15);
  await page.locator('.activity-content .pagination').getByRole('button',{name:'Next',exact:true}).click();
  assert.equal(await page.locator('.activity-content tbody tr:visible').first().innerText(),'session-15');
  await page.locator('#activity-search').fill('session-35');
  assert.equal(await page.locator('.activity-content tbody tr:visible').count(),1);
  assert.match(await page.locator('.activity-content .pagination').innerText(),/Page 1 of 1/);
  assert.deepEqual(errors,[]);console.log('PASS: modes, host override, reload persistence, scored-only explanation, Cedar validation/rollback, responsive layouts');
 }finally{if(browser)await browser.close();child.kill('SIGTERM');await rm(root,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
