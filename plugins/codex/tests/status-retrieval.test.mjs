import assert from 'node:assert/strict'
import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'
import { done, quote } from './host-helper.mjs'
import { nativeFixture, lastReceipt, customCall, readCounter } from './native-helper.mjs'

test('installed code mode retrieves pending results without executing the MCP placeholder', {timeout:120000}, async()=>{
  let command,counter
  const statuses=[]
  const fixture=await nativeFixture((body,index)=>{
    assert(index<25,'Status retrieval did not finish')
    assert(!JSON.stringify(body).includes('Patronus native hooks did not handle this call'), 'Status retrieval executed the MCP placeholder')
    if(index===1){
      const call=customCall(body,'exec',`text(await tools.exec_command({cmd:${JSON.stringify(command)}}));`,'source')
      assert(call,'Installed host must expose code mode for this regression')
      return [call]
    }
    const receipt=lastReceipt(body)
    statuses.push(receipt.status)
    if(receipt.status==='pending')return [customCall(body,'exec',`text(await tools.mcp__patronus__patronus_check_result({scan_id:${JSON.stringify(receipt.scan_id)}}));`,'poll-'+index)]
    assert.equal(receipt.status,'approved')
    assert(JSON.stringify(receipt.result).includes('VERSION_0_1_0'))
    return [done()]
  },{}, {codeMode:true,captureHooks:true})
  try{
    counter=join(fixture.cwd,'executions')
    const file=join(fixture.cwd,'manifest.txt')
    await writeFile(file,'VERSION_0_1_0')
    command=`${quote(process.execPath)} -e ${quote(`const fs=require('node:fs');fs.appendFileSync(${JSON.stringify(counter)},'1');process.stdout.write(fs.readFileSync(${JSON.stringify(file)}));`)}`
    await fixture.exec('status-retrieval')
    assert.equal(await readCounter(counter),'1')
    assert.equal(statuses[0],'pending')
    assert.equal(statuses.at(-1),'approved')
    const events=(await readFile(fixture.hookCapture,'utf8')).trim().split('\n').map(JSON.parse)
    assert(events.some(e=>e.hook_event_name==='PreToolUse' && e.tool_name.includes('patronus_check_result')))
    console.log(JSON.stringify({test:'code-mode-status-retrieval',statuses,root:fixture.root}))
  }finally{await fixture.close()}
})

test('stale PreToolUse trust is diagnosed and explicit repair restores status retrieval', {timeout:120000}, async()=>{
  const {run}=await import('./host-helper.mjs')
  const scanner=process.env.PATRONUS_SCANNER_BIN
  let phase='before',submitted=false,placeholder=false,command,counter
  const fixture=await nativeFixture((body,index)=>{
    assert(index<30,'Retrieval did not finish')
    if(!submitted){submitted=true;return [customCall(body,'exec',`text(await tools.exec_command({cmd:${JSON.stringify(command)}}));`,phase+'-source')]}
    if(JSON.stringify(body).includes('Patronus native hooks did not handle this call')){
      assert.equal(phase,'before','Repaired retrieval still executed the placeholder')
      placeholder=true;return [done()]
    }
    const receipt=lastReceipt(body)
    if(receipt.status==='pending')return [customCall(body,'exec',`text(await tools.mcp__patronus__patronus_check_result({scan_id:${JSON.stringify(receipt.scan_id)}}));`,phase+'-poll-'+index)]
    assert.equal(phase,'after')
    assert.equal(receipt.status,'approved')
    assert(JSON.stringify(receipt.result).includes('VERSION_0_1_0'))
    return [done()]
  },{}, {codeMode:true,marketplaceName:'patronus-local'})
  try{
    counter=join(fixture.cwd,'executions')
    const file=join(fixture.cwd,'manifest.txt');await writeFile(file,'VERSION_0_1_0')
    command=`${quote(process.execPath)} -e ${quote(`const fs=require('node:fs');fs.appendFileSync(${JSON.stringify(counter)},'1');process.stdout.write(fs.readFileSync(${JSON.stringify(file)}));`)}`
    const config=join(fixture.env.CODEX_HOME,'config.toml')
    const pre=fixture.trusted.find(h=>h.eventName==='preToolUse')
    assert(pre)
    const text=await readFile(config,'utf8')
    // Reproduce a previously trusted hook whose definition changed during update.
    assert(text.includes(pre.currentHash))
    await writeFile(config,text.replace(pre.currentHash,'sha256:'+ '0'.repeat(64)))
    await fixture.exec('stale-trust', {bypassApprovals:true})
    assert(placeholder,'The original placeholder failure was not reproduced')
    const options={cwd:fixture.cwd,env:{...fixture.env,PATRONUS_CODEX_BIN:process.env.PATRONUS_CODEX_BIN}}
    const status=await run(scanner,['integration','codex','status','--format','json'],options)
    assert.equal(status.code,0,status.stderr)
    assert.equal(JSON.parse(status.stdout).ready,false,'Stale hook trust must not be reported as active')
    const repaired=await run(scanner,['integration','codex','enable'],options)
    assert.equal(repaired.code,0,repaired.stderr)
    phase='after';submitted=false
    await fixture.exec('repaired-trust')
    assert.equal(await readCounter(counter),'11','Each independent source action must execute exactly once')
    const healthy=await run(scanner,['integration','codex','status','--format','json'],options)
    assert.equal(JSON.parse(healthy.stdout).ready,true)
    console.log(JSON.stringify({test:'stale-trust-repair',root:fixture.root}))
  }finally{await fixture.close()}
})
