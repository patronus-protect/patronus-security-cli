import assert from 'node:assert/strict'
import { writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'
import { call, done, quote } from './host-helper.mjs'
import { nativeFixture, lastReceipt, patronusCall } from './native-helper.mjs'

for (const wait of ['0','10000']) {
  test(`installed Codex continues with PII redaction (response wait ${wait})`,{timeout:120000},async()=>{
    const privateEmail='test.author@example.com'
    let command
    const statuses=[]
    const fixture=await nativeFixture(async(body,index)=>{
      assert(index<60,'Too many model requests')
      if(index===1)return [call('exec_command',{cmd:command})]
      assert(!JSON.stringify(body).includes(privateEmail),'Private email reached the model')
      const result=lastReceipt(body)
      statuses.push(result.status)
      if(result.status==='pending'){
        await new Promise(resolve=>setTimeout(resolve,200))
        return [patronusCall(body,'patronus_check_result',{scan_id:result.scan_id},'poll-'+index)]
      }
      assert.equal(result.status,'redacted')
      assert(JSON.stringify(result.result).includes('0.1.0'))
      assert(JSON.stringify(result.result).includes('[REDACTED]'))
      return [done()]
    },{PATRONUS_RESPONSE_WAIT_MS:wait})
    try {
      await writeFile(fixture.env.PATRONUS_CONFIG,'[provider]\nmode="local"\n[ark]\ncategories=["prompt_injection","pii","dlp"]\nmax_level="l1"\ndownload_files=false\n')
      const path=join(fixture.cwd,'manifest.toml')
      await writeFile(path,`version = "0.1.0"\nauthor = "${privateEmail}"\n`)
      command='cat '+quote(path)
      await fixture.exec('auto-redaction')
      assert.equal(statuses.at(-1),'redacted')
      console.log(JSON.stringify({test:'installed-pii-redaction',wait,statuses,root:fixture.root}))
    }finally{await fixture.close()}
  })
}
