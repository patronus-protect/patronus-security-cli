import assert from 'node:assert/strict'
import test from 'node:test'
import { autoRedact } from '../../deepseek/src/auto-redaction.ts'
import { receipt } from '../../deepseek/src/receipts.ts'
import type { ScanResult } from '../../deepseek/src/protocol.ts'
import { handleHook } from '../src/hooks.ts'

const original = 'PRIVATE-EMAIL-CANARY'
const safe = 'version = "0.1.0"\nauthor = "[REDACTED]"'
const dangerous: ScanResult = {
  scan_id: 'a'.repeat(32), status: 'dangerous', redacted_available: true,
  findings: [{category:'pii'}],
  coverage: {complete:true,fields_total:1,fields_scanned:1,bytes_total:42,bytes_scanned:42},
}
const masked = async () => ({scan_id:dangerous.scan_id,status:'redacted' as const,result:safe})

test('PII and DLP automatically deliver the scanner redaction, never an attached original', async () => {
  for (const findings of [[{category:'pii'}], [{category:'dlp'}], [{category:'pii'},{category:'dlp'}]]) {
    const result = await autoRedact({...dangerous,findings,result:original}, masked)
    assert.equal(result.status,'redacted')
    assert.equal(result.result,safe)
    assert.doesNotMatch(JSON.stringify(receipt(result)), /PRIVATE-EMAIL-CANARY/)
    assert.match(JSON.stringify(receipt(result)), /continue the task/)
  }
})

test('pending, incomplete, mixed injection, and malformed coverage never auto-release text', async () => {
  const cases: ScanResult[] = [
    {...dangerous,status:'pending'}, {...dangerous,status:'incomplete'},
    {...dangerous,redacted_available:false}, {...dangerous,findings:[]},
    {...dangerous,findings:[{category:'pii'},{category:'prompt_injection'}]},
    {...dangerous,coverage:{complete:true}},
    {...dangerous,coverage:{complete:true,fields_total:2,fields_scanned:1,bytes_total:42,bytes_scanned:42}},
  ]
  for (const input of cases) {
    let calls=0
    assert.equal(await autoRedact(input,async()=>{calls++;return masked()}),input)
    assert.equal(calls,0)
  }
})

test('failed or mismatched redaction preserves the manual retrieval route without original text', async () => {
  for (const read of [
    async()=>{throw Error(original)},
    async()=>({scan_id:'b'.repeat(32),status:'redacted' as const,result:original}),
    async()=>({scan_id:dangerous.scan_id,status:'unavailable' as const}),
  ]) {
    const result=await autoRedact(dangerous,read)
    assert.equal(result,dangerous)
    const visible=JSON.stringify(receipt(result))
    assert.match(visible,/patronus_read_redacted/)
    assert(!visible.includes(original))
  }
})

const safety={async isQuarantined(){return false},async quarantine(){},async arm(){},async hasPending(){return false}}
const protocol=async(_c:unknown,_r:unknown,run:()=>Promise<any>)=>run()
for (const host of ['codex','claude'] as const) {
  test(`${host} delivers automatic masked output at the native tool boundary and status retrieval`, async()=>{
    const result=await autoRedact(dangerous,masked)
    for(const event of ['PostToolUse','PreToolUse']) {
      const value=await handleHook(host,event,{
        hook_event_name:event,session_id:'redaction-test',cwd:'/private/tmp',tool_use_id:'call-1',
        tool_name:event==='PreToolUse'?'mcp__patronus__patronus_check_result':'mcp__fixture__read',
        tool_input:{scan_id:dangerous.scan_id},tool_response:{content:[{type:'text',text:original},{type:'image',data:'MEDIA'}]},
      },{},async()=>result as any,safety,undefined,protocol)
      assert(!JSON.stringify(value).includes(original))
      assert.match(JSON.stringify(value),/REDACTED/)
      assert.match(JSON.stringify(value),/redacted/)
    }
  })
}
