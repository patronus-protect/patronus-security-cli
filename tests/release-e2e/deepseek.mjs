import assert from 'node:assert/strict'
import { copyFile, mkdir, mkdtemp, readFile, writeFile, chmod, readdir, cp } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { join, resolve } from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { checked, scannerConfig, manifest, email, injectionDocument, injectionRedacted, treeDigest, seedSettings } from './common.mjs'
import { run } from '../../plugins/codex/tests/host-helper.mjs'

export async function deepseekSetup(reportRoot) {
  const harness = resolve(process.env.DSH_SOURCE_ROOT)
  const require = createRequire(join(harness,'package.json'))
  const metadata = JSON.parse(await readFile(new URL('../../plugins/deepseek/package.json',import.meta.url),'utf8'))
  const revision = await checked('git',['rev-parse','HEAD'],{cwd:harness})
  assert.equal(revision.stdout.trim(),metadata.patronusProbe.harnessCommit,'Unexpected DeepSeek host revision')
  await mkdir(join(harness,'tmp'),{recursive:true})
  const root = await mkdtemp(join(harness,'tmp/patronus-release-'))
  const home = join(root,'home'), workspace = join(root,'workspace')
  await mkdir(workspace,{recursive:true})
  const installed = join(home,'profiles/headless/node_modules/@patronus/deepseek-security')
  const resolver = join(root,'resolver.mjs')
  await writeFile(resolver, `const sources={'@deepseek-ai/dsh-llm':${JSON.stringify(pathToFileURL(join(harness,'packages/llm/llm/src/index.ts')).href)},'@deepseek-ai/dsh-tools':${JSON.stringify(pathToFileURL(join(harness,'packages/core/tools/src/index.ts')).href)}};export function resolve(specifier,context,next){if(sources[specifier] && context.parentURL?.startsWith(${JSON.stringify(pathToFileURL(installed).href+'/')}))return next(sources[specifier],context);return next(specifier,context)}`)
  const register = join(root,'register.mjs')
  await writeFile(register,`import {register} from 'node:module';register(${JSON.stringify(pathToFileURL(resolver).href)});`)
  const dsh = process.env.PATRONUS_DSH_BIN || join(root,'dsh')
  if (!process.env.PATRONUS_DSH_BIN) {
    const prefix = ['--import',require.resolve('tsx/esm'),'--import',register,join(harness,'apps/cli/src/bin.ts')]
    await writeFile(dsh,`#!${process.execPath}\nimport {spawnSync} from 'node:child_process';const r=spawnSync(${JSON.stringify(process.execPath)},[...${JSON.stringify(prefix)},...process.argv.slice(2)],{stdio:'inherit'});process.exit(r.status??1);`)
    await chmod(dsh,0o700)
  }
  const env = {...process.env,DSH_HOME:home,DSH_TELEMETRY_DISABLED:'1',TSX_TSCONFIG_PATH:join(harness,'tsconfig.base.json'),PATRONUS_DSH_BIN:dsh,PATRONUS_DATA_DIR:join(root,'private-data'),PATRONUS_E2E_MOCK_HELPERS:pathToFileURL(join(harness,'packages/core/agent-loop/tests/mock-adapter.ts')).href,npm_config_cache:join(root,'npm-cache')}
  if (process.env.PATRONUS_DSH_BIN) env.NODE_OPTIONS = `${env.NODE_OPTIONS || ''} --import ${require.resolve('tsx/esm')}`.trim()
  for(const key of ['OPENAI_API_KEY','CODEX_API_KEY','ANTHROPIC_API_KEY','DEEPSEEK_API_KEY']) delete env[key]
  // Packaged bytes only: never run prepack or compile the plugin under test.
  let tarball = process.env.PATRONUS_DEEPSEEK_TARBALL
  if (!tarball) {
    const packageRoot = join(root,'candidate')
    await mkdir(packageRoot)
    for (const path of ['package.json','dist','cordis.patch.yml','skills']) await cp(join(process.env.PATRONUS_DEEPSEEK_PLUGIN_ROOT,path),join(packageRoot,path),{recursive:true})
    // assets are optional on older installed packages.
    try { await cp(join(process.env.PATRONUS_DEEPSEEK_PLUGIN_ROOT,'assets'),join(packageRoot,'assets'),{recursive:true}) } catch(error) { if(error.code!=='ENOENT')throw error }
    await checked('npm',['pack','--ignore-scripts','--pack-destination',root],{cwd:packageRoot,env})
    tarball = join(root,(await readdir(root)).find(name=>name.endsWith('.tgz')))
  }
  await checked(dsh,['plugin','--profile','headless','add',tarball,'--ignore-scripts'],{cwd:workspace,env})
  const artifact = await treeDigest(installed)
  const model = join(home,'profiles','patronus-release-model.mjs')
  await copyFile(fileURLToPath(new URL('./deepseek-model.mjs',import.meta.url)),model)
  return {root,home,workspace,installed,dsh,env,tarball,artifact,model,revision:revision.stdout.trim(),reportRoot}
}

export async function deepseekFlow(setup, flow) {
  const {root,home,workspace,dsh,env,installed,tarball,model} = setup
  const flowEnv = {...env}
  if (flow === 'remote-fail-open') delete flowEnv.PATRONUS_API_KEY
  const dir = join(root,flow); await mkdir(dir)
  const config = join(dir,'scanner.toml'), document = join(dir,'manifest.toml'), blocker=join(dir,'queue-blocker.txt'), counter=join(dir,'executions')
  const evidence = join(dir,'evidence.json'), requests=join(dir,'requests.json')
  await writeFile(config,scannerConfig+(flow==='queue-backlog'?'[chunking]\ntarget_bytes=4\noverlap_bytes=0\nprefer_line_boundaries=false\n':''))
  await writeFile(document,flow==='read-redacted'?injectionDocument:manifest+(flow==='auto-pii'?`author = "${email}"\n`:''))
  if(flow==='queue-backlog') await writeFile(blocker,'benign queue blocker\n'.repeat(64))
  const patch = (executable, degraded = false) => [
    {id:'patronus-security',config:{executable,configPath:config,stateDir:join(dir,'scanner-state'),responseWaitMs:0}},
    {id:'agent-default-model',config:{provider:'release-model',model:'scripted'}},
    {id:'llm-deepseek',disabled:true},{id:'session-title-llm',disabled:true},{id:'typert-loader',disabled:true},
    {insert:[{id:'release-model',name:model,config:{flow,degraded,document,blocker,counter,evidence,requests,...(flow==='read-redacted'?{expectedRedacted:injectionRedacted}:{})}}]},
  ]
  const patchPath=join(home,'profiles/headless/cordis.patch.yml')
  await writeFile(patchPath,JSON.stringify(patch(process.env.PATRONUS_SCANNER_BIN)))
  const execute = async label => {
    const result = await run(dsh,['--profile','headless','Read the local fixture document.'],{cwd:workspace,env:flowEnv})
    await writeFile(join(dir,label+'.json'),JSON.stringify(result,null,2))
    return result
  }
  try {
    if(flow==='upgrade') {
      const verifySettings=await seedSettings(env.PATRONUS_DATA_DIR)
      // Install a distinct previous package through the host, then update publicly.
      const previous = join(dir,'previous')
      await mkdir(previous)
      for(const path of ['package.json','dist','cordis.patch.yml','skills']) await cp(join(installed,path),join(previous,path),{recursive:true})
      const metadata = JSON.parse(await readFile(join(previous,'package.json'),'utf8'))
      metadata.version += '-e2e.previous'
      await writeFile(join(previous,'package.json'),JSON.stringify(metadata))
      await checked('npm',['pack','--ignore-scripts','--pack-destination',dir],{cwd:previous,env})
      const priorTarball=join(dir,(await readdir(dir)).find(name=>name.endsWith('.tgz')))
      await checked(dsh,['plugin','--profile','headless','add',priorTarball,'--ignore-scripts'],{cwd:workspace,env})
      assert.notEqual((await treeDigest(installed)).sha256,setup.artifact.sha256)
      const before=await readFile(patchPath,'utf8')
      await checked(process.env.PATRONUS_SCANNER_BIN,['integration','deepseek','update','--source',tarball],{cwd:workspace,env})
      assert.equal(await readFile(patchPath,'utf8'),before,'Update changed profile settings')
      assert(!(await readFile(join(installed,'dist/index.js'),'utf8')).includes('STALE_RELEASE_PLUGIN'))
      assert.equal((await treeDigest(installed)).sha256,setup.artifact.sha256,'Updated installed bytes differ from candidate')
      await verifySettings()
    }
    if(flow==='outage-recovery') {
      await writeFile(patchPath,JSON.stringify(patch(join(dir,'absent-scanner'),true)))
      const outage=await execute('outage')
      assert.equal(outage.code,0,outage.stderr)
      assert(outage.stdout.includes('RELEASE_FLOW_PASSED'),'Degraded CLI task did not finish')
      const degradedProof=JSON.parse(await readFile(evidence,'utf8'))
      assert.equal(degradedProof.degradedWarning,true)
      assert.equal(degradedProof.originalAvailable,true)
      assert.equal(await readFile(counter,'utf8'),'1')
      await writeFile(patchPath,JSON.stringify(patch(process.env.PATRONUS_SCANNER_BIN)))
    }
    const result=await execute('host')
    assert.equal(result.code,0,result.stderr)
    assert(result.stdout.includes('RELEASE_FLOW_PASSED'),'CLI did not finish the scripted task')
    const proof=JSON.parse(await readFile(evidence,'utf8'))
    assert.equal(proof.completed,true)
    if(flow==='queue-backlog') assert.equal(proof.queueBackpressureVisible,true)
    assert.equal(await readFile(counter,'utf8'),flow==='outage-recovery'||flow==='queue-backlog'?'11':'1')
    return {...proof,...(flow==='outage-recovery'?{degradedWarning:true,originalAvailable:true,recovered:true,sourceExecutions:2}:{}),root:dir}
  } catch(error) { error.evidenceRoot=dir; error.message+=`\nDeepSeek evidence: ${dir}`;throw error }
}
