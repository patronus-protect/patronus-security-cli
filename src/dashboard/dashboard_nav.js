'use strict';
(() => {
 const body=document.body,sidebar=document.getElementById('local-sidebar');if(!sidebar)return;
 const toggle=document.getElementById('local-menu'),collapse=document.getElementById('local-collapse'),backdrop=document.getElementById('local-backdrop');
 const mobile=()=>matchMedia('(max-width: 900px)').matches;
 function close(){body.classList.remove('navigation-open');toggle.setAttribute('aria-expanded','false');backdrop.hidden=true;}
 toggle.addEventListener('click',()=>{const open=!body.classList.contains('navigation-open');body.classList.toggle('navigation-open',open);toggle.setAttribute('aria-expanded',String(open));backdrop.hidden=!open;});
 backdrop.addEventListener('click',close);
 collapse.addEventListener('click',()=>{if(mobile()){close();return;}const collapsed=body.classList.toggle('sidebar-collapsed');collapse.setAttribute('aria-expanded',String(!collapsed));collapse.setAttribute('aria-label',collapsed?'Expand sidebar':'Collapse sidebar');});
 for(const label of sidebar.querySelectorAll('label[for]')){
  label.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();label.click();}});
  label.addEventListener('click',()=>{close();});
 }
 const descriptions={overview:['Local protection','Manage your agent protection and review activity on this device.'],api:['Scan content','Run an explicit security check.'],policies:['Detection rules','Configure PII, DLP and injection protection for your agents.'],shell:['Shell & Cedar','Configure command decisions and your Cedar policies.'],'get-started':['Set up your agents','Connect Patronus to your local agent tools.'],settings:['Local settings','Choose how protection runs on this device.'],commands:['Commands','Use Patronus from your terminal and agent sessions.']};
 for(const radio of document.querySelectorAll('.tab-radio'))radio.addEventListener('change',()=>{const copy=descriptions[radio.id.slice(4)];if(copy){document.querySelector('.hero h1').textContent=copy[0];document.querySelector('.hero p').textContent=copy[1];}document.querySelector('.hero-actions')?.toggleAttribute('hidden',radio.id!=='tab-overview');window.scrollTo(0,0);});
 for(const button of document.querySelectorAll('[data-open-tab]'))button.addEventListener('click',()=>{const radio=document.getElementById(button.dataset.openTab);radio.checked=true;radio.dispatchEvent(new Event('change'));});
 document.addEventListener('keydown',event=>{if(event.key==='Escape')close();});
})();
