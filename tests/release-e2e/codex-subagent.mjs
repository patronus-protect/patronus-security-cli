import assert from 'node:assert/strict'
import { writeFile, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { nativeFixture, customCall, lastReceipt, namespaceCall, readCounter } from '../../plugins/codex/tests/native-helper.mjs'
import { done, quote, run } from '../../plugins/codex/tests/host-helper.mjs'
import { checked, scannerConfig, manifest, marker } from './common.mjs'

// Reproduce an already-loaded parent retaining stale trust after repair on disk.
// Then resume that SAME parent in a fresh process and retrieve its existing scan.
let command, submitted=false, childDone=false, spawned=false, blocked=false
let phase='stale', scanId, recoveryCalls=0, recovered=false
const states=[]
const fixture=await nativeFixture(async (body,index)=>{
  assert(index<35,'Subagent recovery did not finish')
  const visible=JSON.stringify(body.input)
  if(phase==='recovery'){
    if(recoveryCalls++>0){
      const receipt=lastReceipt(body);states.push(receipt.status)
      assert.equal(receipt.scan_id,scanId)
      if(receipt.status==='approved'){
        assert(JSON.stringify(receipt.result).includes(marker));recovered=true;return [done()]
      }
      assert.equal(receipt.status,'pending')
    }
    return [customCall(body,'exec',`text(await tools.mcp__patronus__patronus_check_result({scan_id:${JSON.stringify(scanId)}}));`,'recover-'+index)]
  }
  const isChild=(body.input??[]).some(item=>
    (item.type==='agent_message' && item.recipient==='/root/release_child') ||
    (item.type==='message' && item.role==='user' && item.content?.some(part=>part.type==='input_text' && part.text==='Read the fixture document.'))
  )
  if(isChild){
    if(!submitted){submitted=true;return [customCall(body,'exec',`text(await tools.exec_command({cmd:${JSON.stringify(command)}}));`,'child-source')]}
    if(visible.includes('Patronus native hooks did not handle this call')){blocked=true;childDone=true;return [done()]}
    const receipt=lastReceipt(body);states.push(receipt.status)
    assert.equal(receipt.status,'pending');scanId=receipt.scan_id
    return [customCall(body,'exec',`text(await tools.mcp__patronus__patronus_check_result({scan_id:${JSON.stringify(scanId)}}));`,'child-check-'+index)]
  }
  if(!spawned){
    spawned=true
    await checked(process.env.PATRONUS_SCANNER_BIN,['integration','codex','enable'],{cwd:fixture.cwd,env:{...fixture.env,PATRONUS_CODEX_BIN:process.env.PATRONUS_CODEX_BIN}})
    const group=body.tools.find(item=>item.type==='namespace'&&item.tools.some(t=>t.name==='spawn_agent'))
    assert(group,'Missing subagent tools')
    return [namespaceCall(body,group.name,'spawn_agent',{task_name:'release_child',fork_turns:'none',message:'Read the fixture document.'},'spawn')]
  }
  if(childDone)return [done()]
  return [customCall(body,'exec','await new Promise(resolve=>setTimeout(resolve,300));text("waiting for child");','parent-wait-'+index)]
}, {}, {codeMode:true,subagents:true,captureHooks:true,marketplaceName:'patronus-local',lifecycle:true,tempRoot:process.platform==='darwin'?'/private/tmp':undefined})
try{
  fixture.env.PATRONUS_DATA_DIR=join(fixture.root,'private-data')
  await writeFile(fixture.env.PATRONUS_CONFIG,scannerConfig)
  const path=join(fixture.cwd,'manifest.toml'),counter=join(fixture.cwd,'executions')
  await writeFile(path,manifest)
  command=`${quote(process.execPath)} -e ${quote(`const fs=require('node:fs');fs.appendFileSync(${JSON.stringify(counter)},'1');process.stdout.write(fs.readFileSync(${JSON.stringify(path)}));`)}`
  const config=join(fixture.env.CODEX_HOME,'config.toml')
  const current=fixture.trusted.find(h=>h.key.startsWith('patronus-security@') && h.eventName==='preToolUse').currentHash
  const text=await readFile(config,'utf8');assert(text.includes(current))
  await writeFile(config,text.replace(current,'sha256:'+'0'.repeat(64)))
  // Allow the synthetic tool action, but do NOT bypass hook trust.
  const first=await fixture.exec('stale-subagent',{bypassApprovals:true,ephemeral:false})
  assert(blocked && scanId,'The reported stale-session failure was not reproduced')
  assert.equal(await readCounter(counter),'1')
  const thread=first.stdout.trim().split('\n').map(JSON.parse).find(event=>event.type==='thread.started').thread_id
  phase='recovery'
  const result=await run(process.env.PATRONUS_CODEX_BIN,['exec','resume','--skip-git-repo-check','--json',thread,'Retrieve the pending fixture result.'],{cwd:fixture.cwd,env:fixture.env})
  await writeFile(join(fixture.root,'recovery-host.json'),JSON.stringify(result))
  await writeFile(join(fixture.root,'recovery-requests.json'),JSON.stringify(fixture.server.requests))
  assert.equal(fixture.server.errors.length,0,fixture.server.errors.map(error=>error.stack).join('\n'))
  assert.equal(result.code,0,result.stderr);assert(recovered,'Resume did not retrieve the existing result')
  assert.equal(await readCounter(counter),'1','Recovery reran the source action')
  console.log(JSON.stringify({passed:true,blockedBeforeReload:blocked,recoveredAfterResume:recovered,states,sourceExecutions:1,root:fixture.root}))
}finally{console.log('Evidence: '+fixture.root);await fixture.close()}
