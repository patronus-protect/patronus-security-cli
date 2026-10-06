import dashboardCss from '../../../src/dashboard/dashboard.css'
import inter from '../../../src/dashboard/assets/inter-latin.woff2'
import manrope from '../../../src/dashboard/assets/manrope-latin.woff2'
import interLicense from '../../../src/dashboard/assets/Inter-OFL.txt'
import manropeLicense from '../../../src/dashboard/assets/Manrope-OFL.txt'
import icon from '../../codex/assets/icon.png'

const encoded = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64')
const licenseText = (interLicense + '\n\n' + manropeLicense).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')

/** A navigation surface, never evidence that runtime protection is active. */
export const homeUri = 'ui://patronus/home'
export const homeTool = {
  name: 'patronus_open_home',
  title: 'Patronus Security',
  description: 'Open the Patronus Security home with setup, dashboard and explicit scan starters. This navigation view does not scan content or verify runtime protection. Use the setup workflow to check CLI installation and hook trust.',
  inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  _meta: { ui: { resourceUri: homeUri }, 'openai/ui': { entrypoints: [{ type: 'global' }, { type: 'thread' }] } },
}

function shieldMarkup() { return '<svg viewBox="0 0 80 88" fill="none"><path d="M40 5C30 13 19 15 10 16v25c0 18 13 31 30 41 17-10 30-23 30-41V16c-9-1-20-3-30-11Z" stroke="currentColor" stroke-width="3"/><path d="m26 43 10 10 20-23" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>' }

export function renderHome(mode: 'local' | 'api' = 'local') {
const api = mode === 'api'
const prompts = api ? {
  status: 'Help me connect my Patronus account to the hosted API MCP using host OAuth. Do not run a scan to test sign-in.',
  setup: 'Set up Patronus Security from scratch using the official released CLI instructions at https://github.com/patronus-protect/patronus-security-cli/blob/main/INSTALL.md. Check whether the CLI is installed first. Let me choose CLI only or local hooks; explain and review the hooks before enabling trust. Preserve my processing provider. Verify installation and actual protection separately.',
  dashboard: 'Open https://control.patronus.studio so I can review my account usage.',
  file: 'Help me choose the exact files or repository scope for an explicit Patronus API scan. Wait for my selection before scanning.',
  repo: 'Help me choose the exact Space or Pages for an explicit Patronus API scan. Wait for my selection before fetching or scanning.',
  url: 'Help me choose the exact URL for a Patronus API scan. Wait for my URL before scanning.',
  server: 'Help me choose the exact MCP server URL for a Patronus API metadata scan. Wait for my URL before scanning.'
} : {
  status: 'Check my Patronus setup, CLI installation and Codex hook trust. Explain any unverified protection.',
  setup: 'Help me set up Patronus Security for local Codex chats using the Patronus setup workflow.',
  dashboard: 'Open my local Patronus Security dashboard.',
  file: 'Help me choose the exact file path for an explicit Patronus scan. Wait for my path before scanning.',
  repo: 'Help me choose the exact repository path for an explicit Patronus scan. Wait for my path before scanning.'
}
const apiSurface = `<section class="workspace-hero"><span class="eyebrow">Patronus Security</span><h1>Your context.<br><span>Your control.</span></h1><p>Check content before it enters your AI workflow.</p><div class="home-actions"><button class="button" data-view="setup">Set up Patronus →</button><button class="button secondary" data-open="https://control.patronus.studio">Dashboard &amp; Usage ↗</button></div></section>
<section class="feature-grid" aria-label="Get started with Patronus"><article class="feature-card scan-feature"><div><span class="eyebrow">Scan with confidence</span><h2>What would you like<br>to scan today?</h2><p>Check text, documents, URLs and MCP servers right here.</p><button class="button" data-view="scan">Start a scan →</button></div><div class="scan-art" aria-hidden="true"><div class="art-shield">${shieldMarkup()}</div><div class="art-row"><i></i> Prompt Injection</div><div class="art-row"><i></i> Sensitive data</div><div class="art-row"><i></i> MCP metadata</div></div></article><article class="feature-card setup-feature"><span class="eyebrow">Your setup</span><h2>Protection that fits<br>your workflow.</h2><p>Start with API scans. Add the CLI and local hooks when you need them.</p><div class="setup-art" aria-hidden="true"><span>Plugin</span><b>→</b><span>CLI</span><b>→</b><span>Hooks</span></div><button class="button secondary" data-view="setup">Open setup →</button></article></section>
<section class="category-section"><h2>Choose your next step.</h2><div class="category-grid"><button data-scan="text"><strong>Text &amp; Prompts</strong><span>Paste content</span></button><button data-scan="file"><strong>Files</strong><span>Upload a document</span></button><button data-scan="url"><strong>URLs</strong><span>Public website</span></button><button data-scan="server"><strong>MCP server</strong><span>Check metadata</span></button><button data-action="repo" title="Scan Space / Pages"><strong>Space &amp; Pages</strong><span>Choose in chat</span></button><button data-action="file"><strong>Repository</strong><span>Choose scope in chat</span></button></div></section>
<p class="home-foot" title="Selected content is sent to the Patronus API">You choose the content. API scans use your allowance. Opening this page does not start a scan.</p><section class="account-strip"><div><strong>Everything at a glance.</strong><p>Scan activity, usage and account settings in your dashboard.</p></div><button class="button secondary" data-open="https://control.patronus.studio">Open dashboard ↗</button></section>
<dialog id="setup-dialog"><button class="dialog-close" data-close="setup-dialog" aria-label="Close">×</button><span class="eyebrow">Set up once. Expand anytime.</span><h2>Your Patronus setup.</h2><ol class="onboarding"><li><b>Connect the plugin</b><p>The plugin includes the API connection. Sign in with OAuth and allow access during installation. No API key to copy.</p><span class="setup-state">This workspace was loaded through your authenticated Patronus connection.</span></li><li><b>Choose your first scan</b><p>You choose what to scan. API scans use your account allowance.</p><button class="button secondary" data-view="scan">Open scanner</button></li><li><b>Install the optional CLI</b><p>For local repository scans and local processing. The official installer guides you through sign-in and choosing Local, Hybrid or API mode.</p><button class="button secondary" data-action="setup">Set up with Codex →</button><button class="text-button" data-open="https://github.com/patronus-protect/patronus-security-cli/blob/main/INSTALL.md">Installation guide ↗</button></li><li><b>Add hooks now or later</b><p>Choose “Full protection” during CLI onboarding, or add Codex later. The CLI downloads and verifies the released package, then configures the hooks. Review their behavior before enabling them.</p><pre>patronus-security-scanner integration codex install
patronus-security-scanner integration codex status --format json</pre><details><summary>Why use local hooks?</summary><p>SessionStart reads settings; UserPromptSubmit checks prompt text; PreToolUse associates scan receipts with the chat; PostToolUse checks tool results; Stop clears turn state. The local MCP provides scan status and redacted results. Automatic protection requires a supported local session and must be verified there.</p></details></li></ol></dialog>
<dialog id="scan-dialog"><button class="dialog-close" data-close="scan-dialog" aria-label="Close">×</button><span class="eyebrow">Scan your content</span><h2>What would you like to check?</h2><form id="direct-scan"><fieldset class="scan-types"><legend>Content type</legend><div class="scan-type-options" role="group" aria-label="Content type"><button type="button" data-kind="text" aria-pressed="true">Text</button><button type="button" data-kind="file" aria-pressed="false">File</button><button type="button" data-kind="url" aria-pressed="false">URL</button><button type="button" data-kind="server" aria-pressed="false">MCP server</button></div><select id="scan-kind" hidden aria-label="Content type"><option value="text">Text</option><option value="file">File</option><option value="url">URL</option><option value="server">MCP server</option></select></fieldset><label id="text-field">Text<textarea id="scan-text" rows="6" placeholder="Paste the content you want to check…"></textarea></label><label id="url-field" hidden>Public HTTPS address<input id="scan-url" type="url" placeholder="https://example.com"></label><label id="file-field" hidden>Document<input id="scan-file" type="file" accept=".txt,.md,.markdown,.html,.htm,.pdf,.docx"><small>TXT, Markdown, HTML, PDF or DOCX · up to 10 MB</small></label><p>Only the content you select is sent to the Patronus API. Scans use your account allowance.</p><button class="button" id="scan-submit" type="submit">Scan content →</button></form><div id="scan-status" role="status" aria-live="polite"></div><section id="scan-summary" hidden aria-label="Scan results"></section><details id="scan-details" hidden><summary>Technical details</summary><pre id="scan-output" hidden></pre></details></dialog>`
return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Patronus Security</title>
<style>
@font-face{font-family:Inter;font-style:normal;font-weight:100 900;font-display:swap;src:url(data:font/woff2;base64,${encoded(inter)}) format('woff2')}
@font-face{font-family:Manrope;font-style:normal;font-weight:200 800;font-display:swap;src:url(data:font/woff2;base64,${encoded(manrope)}) format('woff2')}
${dashboardCss}
.home-hero{padding:30px 0 28px}.home-hero h1{max-width:720px;font-size:42px;line-height:1.15;margin:12px 0 16px;letter-spacing:-1.2px}.home-hero h1 em{font-style:normal;color:var(--green)}.home-hero p{max-width:630px;font-size:14px;margin-bottom:22px}
.home-actions{display:flex;gap:10px;flex-wrap:wrap}.home-actions .button{font-size:12px;padding:9px 16px}.home-notice{padding:14px 18px;border:1px solid var(--line);border-radius:10px;margin:0 0 24px;background:var(--paper);color:var(--muted);font-size:12px}.home-notice strong{color:var(--ink)}
.home-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.home-card{padding:24px;margin:0;display:flex;flex-direction:column;align-items:flex-start}.home-card h2{font-size:22px;margin:16px 0 12px}.home-card p{font-size:13px;max-width:430px;margin-bottom:24px}.home-card .button{margin-top:auto;font:650 12px Inter,sans-serif;padding:10px 16px}
.home-foot{font-size:11px;margin-top:24px;max-width:900px}#feedback{margin-top:18px;white-space:pre-wrap;font-size:12px;color:var(--muted)}
@media(max-width:760px){.home-hero{padding:16px 0 24px}.home-hero h1{font-size:30px}.home-grid{grid-template-columns:1fr}.home-card{padding:20px}.home-notice{padding:12px 16px}}

/* Patronus product surface: Manrope, ink, blue and softly lit white panels. */
body{background:linear-gradient(180deg,#f4fbff 0,#fff 650px)}main{max-width:1240px;padding:48px 36px 72px}.topbar{max-width:1240px;padding:18px 36px}.brand{font-size:17px}.brand img{width:32px;height:32px}.workspace-hero{text-align:center;padding:28px 0 64px}.workspace-hero h1{font-size:clamp(42px,5.2vw,68px);letter-spacing:-2.7px;line-height:1.06;margin:18px 0 20px;font-weight:650}.workspace-hero h1 span{color:#0099ff}.workspace-hero p{font-size:16px}.workspace-hero .home-actions{justify-content:center}.button{border-radius:10px;padding:12px 19px;background:#000f22;border-color:#000f22;color:white}.button:hover{background:#13263c}.button.secondary{background:white;color:#000f22;border-color:#dce6ef}.feature-grid{display:grid;grid-template-columns:1.25fr 1fr;gap:24px}.feature-card{position:relative;overflow:hidden;border:1px solid #dceaf4;border-radius:24px;padding:34px;background:white;box-shadow:0 14px 40px -28px #000f2255}.feature-card h2{font-size:30px;line-height:1.15;margin:16px 0;letter-spacing:-1px}.feature-card p{max-width:330px;font-size:13px;line-height:1.7}.scan-feature{display:flex;gap:18px;justify-content:space-between;background:linear-gradient(135deg,#fff 40%,#e8f7ff)}.scan-art{min-width:180px;align-self:center;transform:rotate(-5deg)}.art-shield{width:100px;height:110px;margin:0 auto 20px;color:#0099ff;filter:drop-shadow(0 8px 12px #0099ff33)}.art-row{background:#ffffffee;border:1px solid #c7e7fc;border-radius:10px;margin:8px 0;padding:11px 14px;font-size:11px;box-shadow:0 5px 15px #0099ff0d;white-space:nowrap}.art-row i{display:inline-block;width:6px;height:6px;background:#0099ff;border-radius:50%;margin-right:8px}.setup-feature{background:linear-gradient(140deg,#fff,#f3f6fc)}.setup-art{display:flex;gap:12px;align-items:center;margin:24px 0;color:#0084d9}.setup-art span{background:white;border:1px solid #dae6ef;padding:9px 12px;border-radius:9px;color:#000f22;font-size:11px}.category-section{margin:54px 0}.category-section h2{font-size:23px;margin-bottom:24px}.category-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.category-grid button{cursor:pointer;text-align:left;padding:23px;border:1px solid #dceaf4;background:#f6fbff;border-radius:16px;color:#000f22}.category-grid button:nth-child(2n){background:#f5f7fc}.category-grid button:hover{border-color:#0099ff;box-shadow:0 6px 18px #0099ff12}.category-grid strong,.category-grid span{display:block}.category-grid strong{font:650 16px Manrope,sans-serif}.category-grid span{font-size:11px;color:#64748b;margin-top:6px}.account-strip{display:flex;justify-content:space-between;align-items:center;gap:20px;border:1px solid #dceaf4;border-radius:18px;padding:24px 28px;background:linear-gradient(100deg,#eff8ff,#fff)}.account-strip p{margin:5px 0 0;font-size:12px}dialog{padding:32px;border-color:#dceaf4;box-shadow:0 24px 100px #000f2225}dialog h2{font-size:28px;margin:12px 0 24px}.dialog-close{float:right;background:#f1f5f9;border:0;border-radius:8px;width:30px;height:30px;font-size:22px;cursor:pointer}.onboarding{list-style:none;padding:0;counter-reset:step}.onboarding li{counter-increment:step;position:relative;padding:22px 0 22px 44px;border-top:1px solid #e5edf5}.onboarding li:before{content:counter(step);position:absolute;left:0;top:22px;width:28px;height:28px;display:grid;place-items:center;border-radius:9px;background:#e7f5ff;color:#0079c8;font-weight:700}.onboarding p{font-size:12px;line-height:1.65}.setup-state{font-size:11px;color:#0079c8}.text-button{border:0;background:none;color:#0079c8;cursor:pointer;font-size:12px;padding:12px}#scan-summary{display:grid;gap:10px;margin-top:16px}#scan-summary article{border:1px solid #dceaf4;background:#f6fbff;border-radius:12px;padding:16px}#scan-summary article[data-risk="attack"]{border-color:#f1b5b5;background:#fff6f6}#scan-summary h3{margin:0 0 8px;font-size:15px}#scan-summary p{margin:4px 0;font-size:12px}#scan-details{margin-top:16px}#scan-status{margin-top:20px;color:#475569;font-size:13px}#scan-output{max-height:300px;overflow:auto;white-space:pre-wrap}small{display:block;color:#64748b;margin-top:6px}details{font-size:12px}summary{cursor:pointer}#feedback:empty{display:none}
@media(max-width:800px){main{padding:24px 18px 48px}.topbar{padding:14px 18px}.workspace-hero{padding:22px 0 40px}.workspace-hero h1{letter-spacing:-1.8px}.feature-grid{grid-template-columns:1fr}.feature-card{padding:26px}.category-grid{grid-template-columns:repeat(2,1fr)}.account-strip{align-items:flex-start;flex-direction:column}.scan-art{min-width:140px}.art-row{font-size:10px;padding:9px}.feature-card h2{font-size:27px}}@media(max-width:460px){.scan-art{display:none}.category-grid button{padding:18px}.workspace-hero p{font-size:14px}}

/* Dialogs share the workspace's typography and blue selection accents. */
dialog{box-sizing:border-box;width:min(640px,calc(100vw - 32px));max-height:calc(100dvh - 48px);padding:36px;border:1px solid #e0eaf2;border-radius:24px;background:#fff;color:#000f22;box-shadow:0 32px 120px #000f2233;overflow:auto}dialog::backdrop{background:#000f2259;backdrop-filter:blur(6px)}dialog h2{font-family:Manrope,sans-serif;font-size:28px;line-height:1.25;letter-spacing:-.8px;margin:14px 36px 28px 0}.dialog-close{float:none;position:absolute;top:24px;right:24px;width:34px;height:34px;border-radius:50%;background:#f0f6fa;color:#475569;display:grid;place-items:center}.dialog-close:hover{background:#e4f2fb;color:#000f22}#direct-scan{display:grid;gap:20px}#direct-scan label,.scan-types legend{font:600 12px Inter,sans-serif;color:#334155}#direct-scan label{display:grid;gap:9px}#direct-scan p{font-size:12px;line-height:1.7;color:#64748b;margin:0}#direct-scan input,#direct-scan textarea{box-sizing:border-box;width:100%;font:400 14px Inter,sans-serif;color:#000f22;background:#fbfdff;border:1px solid #dce6ef;border-radius:12px;padding:14px 16px;transition:border-color .15s,box-shadow .15s}#direct-scan textarea{resize:vertical;min-height:150px}#direct-scan input:focus-visible,#direct-scan textarea:focus-visible{outline:none;border-color:#0099ff;box-shadow:0 0 0 3px #0099ff18}#direct-scan input[type=file]{padding:10px;font-size:12px;overflow:hidden}#scan-file::file-selector-button{font:600 12px Inter,sans-serif;border:1px solid #d5e7f3;border-radius:8px;background:#eaf6ff;color:#006bad;padding:10px 14px;margin-right:12px;cursor:pointer}.scan-types{padding:0;margin:0;border:0;min-width:0}.scan-types legend{margin-bottom:10px}.scan-type-options{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;padding:5px;background:#f1f6fa;border:1px solid #e5edf3;border-radius:13px}.scan-type-options button{font:600 12px Inter,sans-serif;background:transparent;border:1px solid transparent;border-radius:9px;padding:11px 6px;color:#64748b;cursor:pointer}.scan-type-options button[aria-pressed=true]{background:white;border-color:#cde8fa;color:#0077c5;box-shadow:0 2px 5px #000f2208}.scan-type-options button:hover{color:#0077c5}.scan-type-options button:focus-visible,.dialog-close:focus-visible{outline:2px solid #0099ff;outline-offset:2px}#scan-submit{width:100%;font-size:13px;padding:14px}#scan-status{line-height:1.65}#scan-status:empty{display:none}#scan-summary[hidden],#direct-scan [hidden]{display:none}#scan-summary article{padding:20px;border-radius:14px}#scan-summary h3{font:650 16px Manrope,sans-serif}#scan-details summary{color:#64748b;padding:8px 0}.onboarding p{font-size:13px}.onboarding pre{overflow:auto;background:#f4f8fb;padding:14px;border-radius:10px;font-size:11px}.onboarding details{line-height:1.7}@media(max-width:460px){dialog{padding:26px 22px;max-height:calc(100dvh - 24px);border-radius:20px}dialog h2{font-size:24px}.dialog-close{top:20px;right:18px}.scan-type-options button{font-size:11px;padding:10px 2px}}
</style></head><body><header><div class="topbar"><div class="brand"><img src="data:image/png;base64,${encoded(icon)}" alt="Patronus logo">Patronus Security</div><span class="eyebrow">Codex</span></div></header><main>
${api ? apiSurface : `<section class="home-hero"><span class="eyebrow">Security workspace</span><h1>Your work.<br><em>${api ? 'Checked with Patronus.' : 'Protected by Patronus.'}</em></h1><p>${api ? 'Connect your account, scan the content you choose and review your account usage.' : 'Set up protection for your local Codex chats, review security activity, or start a scan with a scope you choose.'}</p>
<div class="home-actions"><button class="button secondary" data-action="status">${api ? 'Connect account' : 'Check my setup'}</button><button class="button secondary" data-action="file">${api ? 'Scan files / repository' : 'Scan a file'}</button><button class="button secondary" data-action="repo">${api ? 'Scan Space / Pages' : 'Scan a repository'}</button>${api ? '<button class="button secondary" data-action="url">Scan a URL</button><button class="button secondary" data-action="server">Scan an MCP server</button>' : ''}</div></section>
<div class="home-notice"><strong>${api ? 'You choose what gets scanned.' : 'Protection status has not been checked.'}</strong> ${api ? 'Sign in before using authenticated scans. Selected content is sent to the Patronus API and uses your account allowance. Opening this page starts no scan.' : 'Check your setup to verify local protection. Opening this page does not enable or verify it.'}</div>
<section class="home-grid" aria-label="Get started">
<article class="panel home-card"><span class="eyebrow">${api ? 'Optional local tools' : 'Get started'}</span><h2>${api ? 'Add local protection.' : 'Set up your protection.'}</h2><p>${api ? 'Use the CLI for local repository access. Add reviewed and trusted hooks for supported local Codex chats.' : 'Choose how Patronus processes your data and get your local Codex protection ready.'}</p><button class="button" data-action="setup">${api ? 'Explore CLI and hooks' : 'Set up Patronus'} →</button></article>
<article class="panel home-card"><span class="eyebrow">Overview</span><h2>Your security dashboard.</h2><p>Review scan activity, account usage and protection settings in your Patronus dashboard.</p><button class="button" data-action="dashboard">Open dashboard →</button></article>
</section><p class="home-foot">${api ? 'Space access comes from the host’s Pages tools. Local paths require file access or the CLI. API scans check submitted content; automatic runtime interception requires a separate supported local setup.' : 'Local runtime protection requires the installed CLI and trusted hooks. Cloud-orchestrated Work does not run these plugin hooks. If scanning is unavailable, content is identified as unverified. File and repository scans run only when requested.'}</p>
`}
<div id="feedback" role="status" aria-live="polite"></div>
</main><template id="font-license-notices"><pre>${licenseText}</pre></template><script>
const prompts = ${JSON.stringify(prompts)};
let nextId = 1;
const pending = new Map();
const feedback = document.getElementById('feedback');
function request(method, params) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('The host did not respond.')); }, method === 'tools/call' ? 60000 : 8000);
    pending.set(id, { resolve, reject, timer });
    window.parent.postMessage({ jsonrpc: '2.0', id, method, params }, '*');
  });
}
window.addEventListener('message', event => {
  if (event.source !== window.parent || !event.data || event.data.jsonrpc !== '2.0') return;
  const message = event.data;
  const waiter = pending.get(message.id);
  if (!waiter) return;
  clearTimeout(waiter.timer); pending.delete(message.id);
  if (message.error) waiter.reject(new Error('The host could not complete this action.'));
  else waiter.resolve(message.result);
});
const ready = window.parent !== window ? request('ui/initialize', {
  protocolVersion: '2026-01-26', appCapabilities: {}, appInfo: { name: 'Patronus Security', version: '0.1.2' }
}).then(() => { window.parent.postMessage({ jsonrpc: '2.0', method: 'ui/notifications/initialized' }, '*'); return true; }).catch(() => false) : Promise.resolve(false);
document.querySelectorAll('[data-action]').forEach(button => button.addEventListener('click', async () => {
  const text = prompts[button.dataset.action];
  button.disabled = true;
  try {
    if (!await ready) throw new Error('Chat actions are unavailable in this preview.');
    await request('ui/message', { role: 'user', content: [{ type: 'text', text }] });
    feedback.textContent = 'Request sent to the chat. Follow the chat to complete it.';
  } catch (error) { feedback.textContent = error.message + ' You can send this request yourself:\\n' + text; }
  finally { button.disabled = false; }
}));
</script>${api ? `<script>
const setupDialog = document.getElementById('setup-dialog');
const scanDialog = document.getElementById('scan-dialog');
const kind = document.getElementById('scan-kind');
function setKind(value) { kind.value = value; document.querySelectorAll('[data-kind]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.kind === value))); document.getElementById('text-field').hidden = value !== 'text'; document.getElementById('url-field').hidden = !['url','server'].includes(value); document.getElementById('file-field').hidden = value !== 'file'; }
function openScan(value = 'text') { setupDialog.close(); setKind(value); if (!scanDialog.open) scanDialog.showModal(); }
document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => button.dataset.view === 'setup' ? setupDialog.showModal() : openScan()));
document.querySelectorAll('[data-scan]').forEach(button => button.addEventListener('click', () => openScan(button.dataset.scan)));
document.querySelectorAll('[data-close]').forEach(button => button.addEventListener('click', () => document.getElementById(button.dataset.close).close()));
document.querySelectorAll('[data-open]').forEach(button => button.addEventListener('click', async () => { try { if (!await ready) throw new Error('Host links are unavailable in this preview.'); await request('ui/open-link', { url: button.dataset.open }); } catch (error) { feedback.textContent = error.message + ' Address: ' + button.dataset.open; } }));
kind.addEventListener('change', () => setKind(kind.value));
document.querySelectorAll('[data-kind]').forEach(button => button.addEventListener('click', () => setKind(button.dataset.kind)));
function scanData(result) { if (result.isError) throw new Error(result.content?.find(c => c.type === 'text')?.text || 'Scan failed.'); if (result.structuredContent) return result.structuredContent; const text = result.content?.find(c => c.type === 'text')?.text; if (!text) throw new Error('No scan response received.'); return JSON.parse(text); }
async function callScan(name, args) { return scanData(await request('tools/call', { name, arguments: args })); }
function showResults(values) {
  const summary = document.getElementById('scan-summary'); summary.replaceChildren(); summary.hidden = false;
  for (const value of values) { const result = value.result || value; const article = document.createElement('article'); article.dataset.risk = result.safety_status || ''; const heading = document.createElement('h3'); const state = value.status || value.job_status; heading.textContent = result.safety_status === 'attack' ? 'Risk detected' : result.safety_status === 'review' ? 'Review recommended' : result.safety_status === 'safe' ? 'No risk detected in the scanned content' : state === 'failed' ? 'Scan failed' : state === 'completed' ? 'Scan complete' : 'Scan in progress'; article.append(heading);
    const categories = result.categories || (result.verdict ? { injection: result.verdict } : {}); for (const [name, finding] of Object.entries(categories)) { const line = document.createElement('p'); line.textContent = name + ': ' + (finding.class_name || finding.label || 'No verdict available'); article.append(line); }
    const coverage = document.createElement('p'); coverage.textContent = 'Coverage: ' + (result.completion?.state === 'complete' ? 'complete' : 'not yet confirmed'); article.append(coverage); summary.append(article);
  }
}
function ids(data) { const values = [...(data.jobs || []),...(data.job ? [data.job] : []),data]; return [...new Set(values.map(job => job.job_id || job.id).filter(id => /^job_[0-9a-f]{32}$/.test(id)))]; }
document.getElementById('direct-scan').addEventListener('submit', async event => {
  event.preventDefault(); const submit = document.getElementById('scan-submit'); const status = document.getElementById('scan-status'); const output = document.getElementById('scan-output'); submit.disabled = true; output.hidden = true; document.getElementById('scan-details').hidden = true; document.getElementById('scan-summary').hidden = true; status.textContent = 'Starting your scan…';
  try {
    if (!await ready) throw new Error('Direct scans require the connected Patronus plugin.');
    let name, args;
    if (kind.value === 'text') { const text = document.getElementById('scan-text').value; if (!text.trim()) throw new Error('Please enter some text.'); name = 'submit_scan'; args = { text }; }
    else if (kind.value === 'file') { const file = document.getElementById('scan-file').files[0]; if (!file) throw new Error('Please choose a file.'); if (file.size > 10000000) throw new Error('The file exceeds 10 MB.'); const bytes = new Uint8Array(await file.arrayBuffer()); let binary = ''; for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i,i+8192)); name = 'scan_file'; args = { name: file.name, data_base64: btoa(binary) }; }
    else { const url = new URL(document.getElementById('scan-url').value); if (url.protocol !== 'https:') throw new Error('Please enter a public HTTPS address.'); name = kind.value === 'server' ? 'scan_server' : 'scan_url'; args = name === 'scan_server' ? { mcp_server_url: url.href } : { url: url.href }; }
    const data = await callScan(name,args); output.textContent = JSON.stringify(data,null,2); output.hidden = false; document.getElementById('scan-details').hidden = false; showResults([data]);
    const jobIds = ids(data); let results = [];
    for (const job_id of jobIds) { let result; for (let attempt = 0; attempt < 20; attempt++) { result = await callScan('get_scan',{job_id}); output.textContent = JSON.stringify([...results,result],null,2); showResults([...results,result]); const state = result.status || result.job?.status || result.job_status; if (['completed','failed'].includes(state)) break; status.textContent = 'Scan in progress. Fetching results…'; await new Promise(resolve => setTimeout(resolve, Math.min(1000 + attempt * 250,3000))); } results.push(result); }
    status.textContent = jobIds.length ? 'Your scan status is shown below. Follow any ongoing scans in your dashboard.' : 'Scan response received.';
  } catch (error) { status.textContent = error.message; }
  finally { submit.disabled = false; }
});
</script>` : ''}</body></html>`
}

export const homeHtml = renderHome()
export const apiHomeHtml = renderHome('api')
