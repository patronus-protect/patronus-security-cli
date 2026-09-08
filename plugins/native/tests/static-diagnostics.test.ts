import assert from 'node:assert/strict'
import test from 'node:test'
import { rm,readFile } from 'node:fs/promises'
import { StaticScanner } from '../../deepseek/src/static.ts'
import { fakeCli,canary } from '../../deepseek/tests/static-fixture.ts'

for(const mode of ['config-error','config-noise','error','noise']) {
  test(`static ${mode} identifies configuration failure without disclosing diagnostics`,async()=>{
    const f=await fakeCli(mode)
    try {
      const result=await new StaticScanner(f,new AbortController().signal).scan({kind:'file',path:f.path},new AbortController().signal)
      assert.equal((result as any).reason,mode.startsWith('config-')?'configuration_unavailable':'scan_unavailable')
      assert(!JSON.stringify(result).includes(canary))
    }finally{await rm(f.root,{recursive:true,force:true})}
  })
}
test('static timeout still terminates a hung scanner and cleans private scratch',async()=>{
  const f=await fakeCli('hang')
  const scanner=new StaticScanner(f,new AbortController().signal,1500)
  try{
    const result=await scanner.scan({kind:'file',path:f.path},new AbortController().signal)
    assert.equal((result as any).reason,'timeout')
    const calls=await f.calls()
    for(const call of calls.filter(c=>c.args[0]==='scan')) {
      await assert.rejects(readFile(call.cwd+'/scan.toml'))
      assert.throws(()=>process.kill(call.pid,0))
    }
  }finally{await scanner.close();await rm(f.root,{recursive:true,force:true})}
})
