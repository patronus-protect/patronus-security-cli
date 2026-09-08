import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { StaticScanner } from '../../deepseek/src/static.ts'
import { handleMcp } from '../src/mcp.ts'

const clean = {schema:'patronus.remote.scan.v1',kind:'url',provider:'api',status:'CLEAN',approved:true,complete:true,categories:['injection','dlp','pii','threat'],findings:[],jobs:1,duration_ms:10}
async function fixture(report: object, exit = 0) {
 const root=await mkdtemp(join(tmpdir(),'patronus-remote-test-')),executable=join(root,'scanner.mjs'),log=join(root,'arguments.json')
 await writeFile(executable,`#!${process.execPath}\nimport {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(log)},JSON.stringify(process.argv.slice(2)));process.stdout.write(${JSON.stringify(JSON.stringify({...report,private_text:'PRIVATE-REMOTE-CANARY'}))});process.exitCode=${exit};`,{mode:0o700})
 return {root,executable,log}
}
const signal=()=>new AbortController().signal

test('native MCP schema exposes URL and named MCP checks',()=>{
 const result:any=handleMcp({jsonrpc:'2.0',id:1,method:'tools/list'})
 const scan=result.result.tools.find((tool:any)=>tool.name==='patronus_scan')
 assert(scan.inputSchema.properties.kind.enum.includes('url'))
 assert(scan.inputSchema.properties.kind.enum.includes('mcp'))
 assert.equal(scan.inputSchema.properties.server.type,'string')
})
for(const kind of ['url','mcp'])test(`explicit ${kind} preserves target and returns only scan metadata`,async()=>{
 const f=await fixture({...clean,kind})
 try {
  const path=kind==='url'?'https://example.org/a?q=1&v=2':'./server config.json'
  const input=kind==='mcp'?{kind,path,server:'chosen'}:{kind,path}
  const result:any=await new StaticScanner({executable:f.executable},signal()).scan(input,signal())
  assert.equal(result.approved,true)
  assert(!JSON.stringify(result).includes('PRIVATE-REMOTE-CANARY'))
  const args=JSON.parse(await readFile(f.log,'utf8'))
  assert.deepEqual(args.slice(-2),['--',path])
  if(kind==='mcp')assert.deepEqual(args.slice(4,6),['--server','chosen'])
 }finally{await rm(f.root,{recursive:true,force:true})}
})
for(const invalid of [{complete:false},{status:['CLEAN']},{approved:true,findings:[{category:'injection',level:'l2',confidence:0.9}]},{approved:false,status:'FINDINGS',findings:[{category:['injection'],level:'l2',confidence:0.9}]}])test(`invalid remote report cannot approve ${JSON.stringify(invalid)}`,async()=>{
 const f=await fixture({...clean,...invalid},invalid.approved===false?1:0)
 try {
  const result:any=await new StaticScanner({executable:f.executable},signal()).scan({kind:'url',path:'https://example.org'},signal())
  assert.equal(result.status,'FAILED');assert.equal(result.approved,false)
  assert(!JSON.stringify(result).includes('PRIVATE-REMOTE-CANARY'))
 }finally{await rm(f.root,{recursive:true,force:true})}
})
