// Contract tests use a simulated MCP App host, never a real ChatGPT session.
const { chromium } = require(process.env.PATRONUS_PLAYWRIGHT_MODULE || 'playwright');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
let browser;
before(async () => { browser = await chromium.launch({ headless: true, ...(process.env.PATRONUS_BROWSER_EXECUTABLE ? { executablePath: process.env.PATRONUS_BROWSER_EXECUTABLE } : {}) }); });
after(async () => { await browser?.close(); });
async function fixture(run) {
  const page = await browser.newPage();
  const calls = [];
  let handler = () => ({ structuredContent: { status: 'completed', safety_status: 'safe', completion: { state: 'complete' } } });
  const source = readFileSync(path.join(__dirname, '../server/mcp_home.ts'), 'utf8');
  const html = JSON.parse(source.split('export const homeHtml = ')[1].trim().replace(/;$/, ''));
  await page.exposeFunction('hostCall', async message => {
    calls.push(message);
    try { return { result: message.method === 'tools/call' ? await handler(message.params) : {} }; }
    catch { return { error: { code: -32000, message: 'Host action failed' } }; }
  });
  await page.route('https://preview.test/**', route => route.fulfill({ contentType: 'text/html', body: route.request().url().endsWith('/home') ? html : `<iframe src="/home" style="width:100%;height:95vh;border:0"></iframe><script>addEventListener('message',async event=>{const m=event.data;if(!m.id)return;const response=await window.hostCall(m);event.source.postMessage({jsonrpc:'2.0',id:m.id,...response},'*')})</script>` }));
  await page.goto('https://preview.test/');
  const ui = page.frameLocator('iframe');
  await ui.getByRole('heading', { name: /Your context/ }).waitFor();
  const tools = () => calls.filter(c => c.method === 'tools/call');
  try { await run({ page, ui, calls, tools, respond: fn => { handler = fn; } }); }
  finally { await page.close(); }
}
async function submit(ui) { await ui.locator('#scan-submit').click(); await ui.locator('#scan-submit').waitFor({ state: 'visible' }); await ui.locator('#scan-submit').evaluate(async el => { while (el.disabled) await new Promise(r => setTimeout(r, 20)); }); }
test('P1: selected text is submitted unchanged and queued work is polled', () => fixture(async ({ui, tools, respond}) => {
  const id = 'job_' + 'a'.repeat(32);
  respond(({name}) => ({ structuredContent: name === 'submit_scan' ? {jobs:[{job_id:id}]} : {status:'completed',result:{safety_status:'safe',completion:{state:'complete'}}} }));
  await ui.locator('[data-scan="text"]').click(); await ui.locator('#scan-text').fill('Exact selected text\nwith second line'); await submit(ui);
  assert.deepEqual(tools().map(c=>c.params.name), ['submit_scan','get_scan']);
  assert.deepEqual(tools()[0].params.arguments,{text:'Exact selected text\nwith second line'});
  assert.deepEqual(tools()[1].params.arguments,{job_id:id});
  assert.match(await ui.locator('#scan-summary').innerText(), /Coverage: complete/);
}));
test('P2: Page selection delegates to the host without fetching or scanning', () => fixture(async ({ui,calls,tools}) => {
  await ui.locator('[data-action="repo"]').click();
  await ui.locator('#feedback').filter({hasText:'Request sent'}).waitFor();
  const message=calls.find(c=>c.method==='ui/message'); assert(message);
  assert.match(message.params.content[0].text,/Wait for my selection before fetching or scanning/);
  assert.equal(tools().length,0);
}));
for (const [kind,name,key,target] of [['url','scan_url','url','https://example.com/public'],['server','scan_server','mcp_server_url','https://example.com/mcp']]) {
  test(`P3/P4: ${kind} uses only the selected endpoint`, () => fixture(async ({ui,tools}) => {
    await ui.locator(`[data-scan="${kind}"]`).click(); await ui.locator('#scan-url').fill(target); await submit(ui);
    assert.equal(tools().length,1); assert.deepEqual(tools()[0].params,{name,arguments:{[key]:target}});
  }));
}
test('P5: navigation and setup do not submit scans or install local tools', () => fixture(async ({ui,calls,tools}) => {
  await ui.locator('[data-view="setup"]').first().click(); await ui.locator('#setup-dialog').waitFor({state:'visible'});
  assert.match(await ui.locator('#setup-dialog').innerText(),/optional CLI/i);
  await ui.locator('#setup-dialog [data-close]').click(); await ui.locator('[data-open="https://control.patronus.studio"]').first().click();
  await ui.locator('[data-open="https://control.patronus.studio"]').first().evaluate(async el=>{while(el.disabled)await new Promise(r=>setTimeout(r,20));});
  await ui.locator('#feedback').evaluate(async ()=>{await new Promise(r=>setTimeout(r,100));});
  assert(calls.some(c=>c.method==='ui/open-link'&&c.params.url==='https://control.patronus.studio')); assert.equal(tools().length,0);
}));
test('N1: denied account surfaces an error with no anonymous fallback', () => fixture(async ({ui,tools,respond}) => {
  respond(()=>({isError:true,content:[{type:'text',text:'Authentication required. Reconnect Patronus.'}]}));
  await ui.locator('[data-scan="text"]').click();await ui.locator('#scan-text').fill('Selected');await submit(ui);
  assert.match(await ui.locator('#scan-status').innerText(),/Authentication required/);
  assert.deepEqual(tools().map(c=>c.params.name),['submit_scan']);assert(await ui.locator('#scan-summary').evaluate(el=>el.hidden));
}));
test('N2: repository access is delegated rather than pretending a remote MCP reads paths', () => fixture(async ({ui,calls,tools}) => {
  await ui.locator('[data-action="file"]').click();await ui.locator('#feedback').filter({hasText:'Request sent'}).waitFor();
  assert.match(calls.find(c=>c.method==='ui/message').params.content[0].text,/exact files or repository scope/);assert.equal(tools().length,0);
}));
for(const [label,kind,value] of [['empty text','text',''],['HTTP URL','url','http://example.com'],['invalid URL','url','not-a-url'],['missing file','file',null]]) {
 test(`N3: ${label} cannot trigger a scan`,()=>fixture(async({ui,tools})=>{
  await ui.locator(`[data-scan="${kind}"]`).click();if(value)await ui.locator('#scan-url').fill(value);
  await submit(ui);assert.equal(tools().length,0);assert(await ui.locator('#scan-summary').evaluate(el=>el.hidden));
 }));
}
test('file upload preserves the selected bytes',()=>fixture(async({ui,tools})=>{
 await ui.locator('[data-scan="file"]').click();await ui.locator('#scan-file').setInputFiles({name:'selected.txt',mimeType:'text/plain',buffer:Buffer.from('Selected bytes')});await submit(ui);
 assert.equal(tools()[0].params.name,'scan_file');assert.equal(Buffer.from(tools()[0].params.arguments.data_base64,'base64').toString(),'Selected bytes');
}));
test('oversized file is rejected before upload',()=>fixture(async({ui,tools})=>{
 await ui.locator('[data-scan="file"]').click();await ui.locator('#scan-file').setInputFiles({name:'large.txt',mimeType:'text/plain',buffer:Buffer.alloc(10000001)});await submit(ui);
 assert.equal(tools().length,0);assert.match(await ui.locator('#scan-status').innerText(),/exceeds 10 MB/);
}));
test('host failure shows no successful verdict and permits retry',()=>fixture(async({ui,tools,respond})=>{
 respond(()=>{throw Error('offline')});await ui.locator('[data-scan="text"]').click();await ui.locator('#scan-text').fill('Selected');await submit(ui);
 assert(await ui.locator('#scan-summary').evaluate(el=>el.hidden));assert.match(await ui.locator('#scan-status').innerText(),/could not complete/);
 respond(()=>({structuredContent:{status:'completed'}}));await submit(ui);assert.equal(tools().length,2);
}));
test('unknown coverage is never displayed as complete and result text is escaped',()=>fixture(async({ui,respond})=>{
 respond(()=>({structuredContent:{status:'completed',categories:{injection:{label:'<img src=x onerror=alert(1)>'}}}}));
 await ui.locator('[data-scan="text"]').click();await ui.locator('#scan-text').fill('Selected');await submit(ui);
 assert.match(await ui.locator('#scan-summary').innerText(),/not yet confirmed/);assert.equal(await ui.locator('#scan-summary img').count(),0);
}));
test('mobile modal fits viewport and selection buttons expose active state',()=>fixture(async({page,ui})=>{
 await page.setViewportSize({width:390,height:844});await ui.locator('[data-scan="file"]').click();await ui.locator('[data-kind="url"]').click();
 assert.equal(await ui.locator('[data-kind="url"]').getAttribute('aria-pressed'),'true');assert(await ui.locator('#file-field').evaluate(el=>el.hidden));
 const frame=page.frames().find(f=>f.url().endsWith('/home'));assert.equal(await frame.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
}));
test('unsupported document response remains an error without a clean verdict',()=>fixture(async({ui,tools,respond})=>{
 respond(()=>({isError:true,content:[{type:'text',text:'Unsupported document format'}]}));
 await ui.locator('[data-scan="file"]').click();await ui.locator('#scan-file').setInputFiles({name:'unsupported.bin',mimeType:'application/octet-stream',buffer:Buffer.from([0,1,2])});await submit(ui);
 assert.equal(tools().length,1);assert.match(await ui.locator('#scan-status').innerText(),/Unsupported document format/);assert(await ui.locator('#scan-summary').evaluate(el=>el.hidden));
}));
