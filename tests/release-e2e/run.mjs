#!/usr/bin/env node
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readdir, copyFile, writeFile } from 'node:fs/promises'
import { tmpdir, homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { checked, digest, treeDigest, evidence, flows } from './common.mjs'

if (process.argv.includes('--help')) {
  console.log(`Release E2E: node tests/release-e2e/run.mjs [--installed] [--host codex|deepseek] [--flow NAME] [--out DIR]
Required: PATRONUS_SCANNER_BIN (installed CLI)
Codex: PATRONUS_CODEX_BIN, PATRONUS_CODEX_PLUGIN_ROOT (installed plugin or extracted release)
DeepSeek: DSH_SOURCE_ROOT (pinned dependency-installed CLI checkout), plus
  PATRONUS_DEEPSEEK_PLUGIN_ROOT (installed package) OR PATRONUS_DEEPSEEK_TARBALL (release)
Flows: ${flows.join(', ')}
No plugin compilation, live model credentials, user-profile changes or silent skips.`)
  process.exit(0)
}
const args=process.argv.slice(2), options={}
while(args.length){const key=args.shift();if(key==='--installed'){options[key]=true;continue}assert(['--host','--flow','--out'].includes(key),`Unknown option ${key}`);assert(args.length,`Missing value for ${key}`);options[key]=args.shift()}
const hosts=options['--host']?[options['--host']]:['codex','deepseek']
assert(hosts.every(host=>['codex','deepseek'].includes(host)))
const selected=options['--flow']?[options['--flow']]:flows
assert(selected.every(flow=>flows.includes(flow)))
const root=options['--out']?resolve(options['--out']):await mkdtemp(join(tmpdir(),'patronus-release-report-'))
await mkdir(root,{recursive:true})
const report={schema:'patronus.release-e2e.v1',startedAt:new Date().toISOString(),scope:{hosts,flows:selected},releaseGate:hosts.length===2&&selected.length===flows.length,installedPreflight:!!options['--installed'],artifacts:{},results:[],passed:false}
async function collect(host,flow,path) {
  if(!path)return
  const destination=join(root,host,flow);await mkdir(destination,{recursive:true})
  for(const name of await readdir(path)) {
    if(name.endsWith('.json') && /host|requests|evidence|outage/.test(name)) await copyFile(join(path,name),join(destination,name))
  }
}
async function save(){
  await evidence(join(root,'report.json'),report)
  const lines=['# Patronus release E2E', '', `Result: ${report.passed?'PASS':report.finishedAt?'FAIL':'RUNNING'}. Full release scope: ${report.releaseGate?'yes':'no'}.`, '', '| Host | Flow | Result |', '| --- | --- | --- |', ...report.results.map(row=>`| ${row.host} | ${row.flow||'setup'} | ${row.status} |`), '', ...report.results.filter(row=>row.error).map(row=>`**${row.host}/${row.flow||'setup'}:** ${row.error.split('\n').slice(0,4).join(' ')}`), '', 'See report.json for artifact hashes and copied host/model evidence.']
  await writeFile(join(root,'report.md'),lines.join('\n')+'\n')
}
try {
  assert(process.env.PATRONUS_SCANNER_BIN,'Missing PATRONUS_SCANNER_BIN')
  report.artifacts.scanner={path:process.env.PATRONUS_SCANNER_BIN,sha256:await digest(process.env.PATRONUS_SCANNER_BIN),version:(await checked(process.env.PATRONUS_SCANNER_BIN,['version'])).stdout.trim()}
  for(const host of hosts){
    let execute
    try {
      if(host==='codex'){
        assert(process.env.PATRONUS_CODEX_BIN && process.env.PATRONUS_CODEX_PLUGIN_ROOT,'Missing installed Codex CLI/plugin path')
        report.artifacts.codex={cli:process.env.PATRONUS_CODEX_BIN,version:(await checked(process.env.PATRONUS_CODEX_BIN,['--version'])).stdout.trim(),plugin:await treeDigest(process.env.PATRONUS_CODEX_PLUGIN_ROOT)}
        if(options['--installed']) {
          const status=JSON.parse((await checked(process.env.PATRONUS_SCANNER_BIN,['integration','codex','status','--format','json'],{env:process.env})).stdout)
          report.artifacts.codex.activeStatus=status
          assert.equal(status.ready,true,'Active Codex installation is not ready; see activeStatus')
        }
        execute=(await import('./codex.mjs')).codexFlow
      } else {
        assert(process.env.DSH_SOURCE_ROOT && (process.env.PATRONUS_DEEPSEEK_PLUGIN_ROOT||process.env.PATRONUS_DEEPSEEK_TARBALL),'Missing installed DeepSeek CLI checkout/plugin artifact')
        const {deepseekSetup,deepseekFlow}=await import('./deepseek.mjs')
        const setup=await deepseekSetup(root)
        report.artifacts.deepseek={hostRevision:setup.revision,hostRoot:process.env.DSH_SOURCE_ROOT,plugin:setup.artifact,tarball:{path:setup.tarball,sha256:await digest(setup.tarball)},root:setup.root}
        if(options['--installed']) {
          assert(process.env.PATRONUS_DEEPSEEK_PLUGIN_ROOT && !process.env.PATRONUS_DEEPSEEK_TARBALL,'Installed preflight requires installed DeepSeek package path')
          const status=JSON.parse((await checked(process.env.PATRONUS_SCANNER_BIN,['integration','deepseek','status','--format','json'],{env:{...setup.env,DSH_HOME:process.env.DSH_HOME||join(homedir(),'.dsh')}})).stdout)
          report.artifacts.deepseek.activeStatus=status
          assert.equal(status.ready,true,'Active DeepSeek profile is not ready; see activeStatus')
        }
        execute=flow=>deepseekFlow(setup,flow)
      }
    } catch(error){
      console.error(`FAIL ${host}/setup: ${error.message}`)
      report.results.push({host,flow:'setup',status:'FAIL',error:error.stack});await save();continue
    }
    for(const flow of selected){
      const started=Date.now()
      console.log(`RUN  ${host}/${flow}`)
      try {const proof=await execute(flow);await collect(host,flow,proof.root);report.results.push({host,flow,status:'PASS',durationMs:Date.now()-started,proof});console.log(`PASS ${host}/${flow}`)}
      catch(error){await collect(host,flow,error.evidenceRoot);report.results.push({host,flow,status:'FAIL',durationMs:Date.now()-started,error:error.stack});console.error(`FAIL ${host}/${flow}: ${error.message}`)}
      await save()
    }
  }
  report.passed=report.results.length===hosts.length*selected.length&&report.results.every(result=>result.status==='PASS')
} catch(error){report.results.push({host:'setup',status:'FAIL',error:error.stack});console.error(error.message)}
finally {
  report.finishedAt=new Date().toISOString();await save()
  console.log(`${report.passed?'PASS':'FAIL'}: ${report.results.filter(result=>result.status==='PASS').length}/${hosts.length*selected.length} flows. Report: ${join(root,'report.json')}`)
  process.exitCode=report.passed?0:1
}
