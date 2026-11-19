'use strict';
(() => {
 function paginate(root=document){
  for(const table of root.querySelectorAll('table')){
   if(table.dataset.paginated)continue;table.dataset.paginated='true';
   const rows=[...(table.tBodies[0]?.rows||[])];
   if(!rows.length||rows.some(row=>row.querySelector('.empty')))continue;
   let page=0,pageSize=15;
   const controls=document.createElement('nav'),previous=document.createElement('button'),label=document.createElement('span'),next=document.createElement('button'),select=document.createElement('select');
   controls.className='pagination';controls.setAttribute('aria-label','Table pages');select.setAttribute('aria-label','Rows per page');
   for(const count of [15,30,50]){const option=document.createElement('option');option.value=count;option.textContent=`${count} / page`;select.append(option);}
   for(const [button,text]of[[previous,'Previous'],[next,'Next']]){button.type='button';button.className='button secondary';button.textContent=text;}
   controls.append(select,previous,label,next);
   const render=()=>{
    const search=(document.getElementById('activity-search')?.value||'').toLowerCase(),type=document.getElementById('activity-type')?.value||'',result=document.getElementById('activity-result')?.value||'';
    const panel=table.closest('.panel'),kind=panel?.dataset.activityKind||'';
    const filtered=rows.filter(row=>!table.closest('.activity-content')||((!search||row.textContent.toLowerCase().includes(search))&&(!type||kind===type||kind==='remote'&&row.dataset.remoteKind===type)&&(!result||(result==='approved'?/approved|clean/i.test(row.textContent):result==='findings'?/dangerous|findings/i.test(row.textContent):row.textContent.toLowerCase().includes(result)))));
    const pages=Math.max(1,Math.ceil(filtered.length/pageSize));page=Math.max(0,Math.min(page,pages-1));rows.forEach(row=>row.hidden=true);filtered.slice(page*pageSize,(page+1)*pageSize).forEach(row=>row.hidden=false);
    label.textContent=`Page ${page+1} of ${pages} · ${filtered.length} entries`;previous.disabled=page===0;next.disabled=page===pages-1;
   };
   previous.onclick=()=>{page--;render();};next.onclick=()=>{page++;render();};select.onchange=()=>{pageSize=Number(select.value);page=0;render();};
   for(const id of ['activity-search','activity-type','activity-result'])document.getElementById(id)?.addEventListener('input',()=>{page=0;render();});
   (table.closest('.table-wrap')||table).insertAdjacentElement('afterend',controls);render();
  }
 }
 paginate();
 const activity=document.querySelector('.activity-content[aria-busy]');
 if(activity)fetch('/api/activity',{headers:{'X-Patronus-Token':document.querySelector('meta[name="patronus-token"]').content}}).then(async response=>{if(!response.ok)throw Error('Activity unavailable');activity.innerHTML=await response.text();activity.removeAttribute('aria-busy');const panels=activity.querySelectorAll('.panel');['file','runtime','remote'].forEach((kind,index)=>{if(panels[index])panels[index].dataset.activityKind=kind;});paginate(activity);}).catch(()=>{activity.setAttribute('aria-busy','false');activity.querySelector('p').textContent='Activity could not be loaded. Reload to retry. Settings remain available.';});
})();
