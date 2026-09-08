import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { nativeFixture, binary } from './native-helper.mjs'
import { run } from './host-helper.mjs'

test('installed Codex resumes a paused chat through patronus on without a model call', {timeout:90000}, async()=>{
 const root=await mkdtemp(join(tmpdir(),'patronus-chat-resume-')), settings=join(root,'plugins.json')
 const fixture=await nativeFixture(()=>assert.fail('Chat controls must never reach the model'), {PATRONUS_PLUGIN_SETTINGS:settings})
 try {
  const off=await run(binary,['exec','--skip-git-repo-check','--json','--sandbox','workspace-write','-C',fixture.cwd,'patronus off'],{cwd:fixture.cwd,env:fixture.env})
  const started=off.stdout.split('\n').filter(Boolean).map(JSON.parse).find(event=>event.type==='thread.started')
  assert(started?.thread_id,off.stderr)
  assert(JSON.parse(await readFile(settings,'utf8').catch(()=>{throw Error(JSON.stringify(off))})).disabled_chats.codex.includes(started.thread_id))
  const on=await run(binary,['exec','resume','--skip-git-repo-check','--json',started.thread_id,'patronus on'],{cwd:fixture.cwd,env:fixture.env})
  assert(!JSON.parse(await readFile(settings,'utf8')).disabled_chats.codex.includes(started.thread_id),on.stderr)
  assert.equal(fixture.server.requests.length,0)
  assert.equal(fixture.server.errors.length,0)
  assert.match(on.stdout,/"input_tokens":0/)
 }finally{await fixture.close();await rm(root,{recursive:true,force:true})}
})
