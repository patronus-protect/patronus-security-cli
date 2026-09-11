'use strict';
(() => {
 const pageSize=15;
 for(const table of document.querySelectorAll('table')){
  const body=table.tBodies[0],rows=body?[...body.rows]:[];
  if(rows.length<=pageSize||rows.some(row=>row.querySelector('.empty')))continue;
  let page=0;
  const controls=document.createElement('nav'),previous=document.createElement('button'),label=document.createElement('span'),next=document.createElement('button');
  controls.className='pagination';controls.setAttribute('aria-label','Table pages');
  for(const [button,text]of[[previous,'Previous'],[next,'Next']]){button.type='button';button.className='button secondary';button.textContent=text;}
  controls.append(previous,label,next);
  const render=()=>{const pages=Math.ceil(rows.length/pageSize);page=Math.max(0,Math.min(page,pages-1));rows.forEach((row,index)=>row.hidden=index<page*pageSize||index>=(page+1)*pageSize);label.textContent=`Page ${page+1} of ${pages} · ${rows.length} entries`;previous.disabled=page===0;next.disabled=page===pages-1;};
  previous.addEventListener('click',()=>{page--;render();});next.addEventListener('click',()=>{page++;render();});
  const wrap=table.closest('.table-wrap');(wrap||table).insertAdjacentElement('afterend',controls);render();
 }
})();
