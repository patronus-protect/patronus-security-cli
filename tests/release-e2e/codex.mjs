import assert from 'node:assert/strict'
import { readFile, writeFile, copyFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { nativeFixture, customCall, lastReceipt, readCounter } from '../../plugins/codex/tests/native-helper.mjs'
import { done, quote } from '../../plugins/codex/tests/host-helper.mjs'
import { checked, scannerConfig, manifest, marker, email, injection, injectionDocument, injectionRedacted, seedSettings } from './common.mjs'

export async function codexFlow(flow) {
  let command, blockerCommand, counter, phase = 'read', submitted = false, remoteAuditSeen = false
  const states = [], tools = []
  const fixture = await nativeFixture((body, index) => {
    assert(index < 40, 'Retrieval exceeded 40 model calls')
    const visible = JSON.stringify(body.input)
    const degradedOutage = flow === 'outage-recovery' && phase === 'outage'
    assert(!visible.includes('Patronus native hooks did not handle this call'), 'Native retrieval reached the MCP placeholder')
    assert(!visible.includes(email), 'Original PII reached the model')
    assert(!visible.includes(injection), 'Original injection reached the model')
    if (degradedOutage) {
      assert(visible.includes('No security scan was completed'), 'Inactive Patronus warning did not reach the model')
      if (!submitted) {
        submitted = true
        tools.push('degraded-source')
        return [customCall(body, 'exec', `text(await tools.exec_command({cmd:${JSON.stringify(command)}}));`, 'outage-source')]
      }
      assert(visible.includes(marker), 'Original unscanned result did not remain available')
      states.push('degraded')
      return [done()]
    }
    if (flow === 'remote-fail-open' && !remoteAuditSeen) {
      if (!submitted) {
        submitted = true
        tools.push('patronus_scan')
        return [customCall(body, 'exec', 'text(await tools.mcp__patronus__patronus_scan({kind:"mcp",path:"https://example.org/"}));', 'remote-audit')]
      }
      assert(visible.includes('remote audit could not authenticate'), 'Unavailable API audit omitted its authentication failure')
      remoteAuditSeen = true
      tools.push('source')
      return [customCall(body, 'exec', `text(await tools.exec_command({cmd:${JSON.stringify(command)}}));`, phase + '-source')]
    }
    if (!submitted) {
      submitted = true
      tools.push('source')
      if (flow === 'queue-backlog') {
        tools.push('queue-blocker')
        return [
          customCall(body, 'exec', `text(await tools.exec_command({cmd:${JSON.stringify(blockerCommand)}}));`, 'queue-blocker'),
          customCall(body, 'exec', `text(await tools.exec_command({cmd:${JSON.stringify(command)}}));`, 'queue-source'),
        ]
      }
      return [customCall(body, 'exec', `text(await tools.exec_command({cmd:${JSON.stringify(command)}}));`, phase + '-source')]
    }
    const receipt = lastReceipt(body)
    states.push(receipt.status)
    if (receipt.status === 'pending') {
      assert(!visible.includes(marker), 'Original content reached the model before approval')
      if (flow === 'queue-backlog') {
        assert.equal(receipt.job_status, 'queued')
        assert.equal(receipt.wait_reason, 'scanner_queue')
        assert.equal(receipt.next_tool, 'patronus_check_result')
        assert.match(receipt.message, /not a scan failure or expiry/)
      }
      tools.push('patronus_check_result')
      const pause = flow === 'queue-backlog' ? 'await new Promise(resolve=>setTimeout(resolve,50));' : ''
      return [customCall(body, 'exec', `${pause}text(await tools.mcp__patronus__patronus_check_result({scan_id:${JSON.stringify(receipt.scan_id)}}));`, 'check-' + index)]
    }
    if (receipt.status === 'dangerous' && flow === 'read-redacted') {
      tools.push('patronus_read_redacted')
      return [customCall(body, 'exec', `text(await tools.mcp__patronus__patronus_read_redacted({scan_id:${JSON.stringify(receipt.scan_id)}}));`, 'redact-' + index)]
    }
    assert.equal(receipt.status, ['auto-pii','read-redacted'].includes(flow) ? 'redacted' : 'approved')
    {
      assert(JSON.stringify(receipt.result).includes(marker))
      assert(JSON.stringify(receipt.result).includes('0.1.0'))
    }
    if (['auto-pii','read-redacted'].includes(flow)) assert(JSON.stringify(receipt.result).includes('[REDACTED]'))
    if (flow === 'read-redacted') assert.equal(receipt.result, injectionRedacted, 'Redaction must change only the injection span')
    return [done()]
  }, {}, {
    tempRoot: process.platform === 'darwin' ? '/private/tmp' : tmpdir(), codeMode: true, marketplaceName: 'patronus-local', lifecycle: true,
    async preparePlugin(destination) {
      if (flow !== 'upgrade') return
      // Previous installed definition differs only in timeout and version.
      const hooksPath = join(destination, 'hooks/hooks.json')
      const hooks = JSON.parse(await readFile(hooksPath, 'utf8'))
      hooks.hooks.PreToolUse[0].hooks[0].timeout -= 1
      await writeFile(hooksPath, JSON.stringify(hooks))
      const path = join(destination, '.codex-plugin/plugin.json')
      const metadata = JSON.parse(await readFile(path, 'utf8'))
      metadata.version += '.e2e-previous'
      await writeFile(path, JSON.stringify(metadata))
    },
  })
  try {
    fixture.env.PATRONUS_DATA_DIR = join(fixture.root, 'private-data')
    if (flow === 'remote-fail-open') delete fixture.env.PATRONUS_API_KEY
    await writeFile(fixture.env.PATRONUS_CONFIG, scannerConfig + (flow === 'queue-backlog'
      ? '[chunking]\ntarget_bytes=4\noverlap_bytes=0\nprefer_line_boundaries=false\n'
      : ''))
    const file = join(fixture.cwd, 'manifest.toml')
    await writeFile(file, flow === 'read-redacted' ? injectionDocument : manifest + (flow === 'auto-pii' ? `author = "${email}"\n` : ''))
    const blocker = join(fixture.cwd, 'queue-blocker.txt')
    if (flow === 'queue-backlog') await writeFile(blocker, 'benign queue blocker\n'.repeat(64))
    counter = join(fixture.cwd, 'executions')
    command = `${quote(process.execPath)} -e ${quote(`const fs=require('node:fs');fs.appendFileSync(${JSON.stringify(counter)},'1');process.stdout.write(fs.readFileSync(${JSON.stringify(file)}));`)}`
    blockerCommand = `${quote(process.execPath)} -e ${quote(`const fs=require('node:fs');fs.appendFileSync(${JSON.stringify(counter)},'1');process.stdout.write(fs.readFileSync(${JSON.stringify(blocker)}));`)}`
    const options = { cwd: fixture.cwd, env: { ...fixture.env, PATRONUS_CODEX_BIN: process.env.PATRONUS_CODEX_BIN } }
    if (flow === 'upgrade') {
      for (const path of ['hooks/hooks.json','.codex-plugin/plugin.json']) await copyFile(join(process.env.PATRONUS_CODEX_PLUGIN_ROOT,path),join(fixture.destination,path))
      const verifySettings = await seedSettings(fixture.env.PATRONUS_DATA_DIR)
      const before = await readFile(join(fixture.env.CODEX_HOME,'config.toml'),'utf8')
      await checked(process.env.PATRONUS_SCANNER_BIN,['integration','codex','update'],options)
      const after = await readFile(join(fixture.env.CODEX_HOME,'config.toml'),'utf8')
      assert.notEqual(before, after, 'Changed hook definition did not refresh trust')
      const status = await checked(process.env.PATRONUS_SCANNER_BIN,['integration','codex','status','--format','json'],options)
      assert.equal(JSON.parse(status.stdout).ready,true)
      await verifySettings()
    }
    if (flow === 'outage-recovery') {
      fixture.env.PATRONUS_SCANNER_BIN = join(fixture.root, 'absent-scanner')
      phase = 'outage'
      await fixture.exec('outage')
      assert.equal(await readCounter(counter), '1', 'Degraded source action did not execute exactly once')
      assert(states.includes('degraded'), 'Degraded result was not observed by the model')
      fixture.env.PATRONUS_SCANNER_BIN = process.env.PATRONUS_SCANNER_BIN
      phase = 'recovered'
      submitted = false
    }
    await fixture.exec(flow)
    const sourceExecutions = flow === 'outage-recovery' || flow === 'queue-backlog' ? 2 : 1
    assert.equal(await readCounter(counter), '1'.repeat(sourceExecutions), 'Unexpected source execution count')
    if (flow === 'remote-fail-open') assert(remoteAuditSeen && tools.includes('patronus_scan') && tools.includes('source'))
    if (flow === 'pending') assert(states.includes('pending') && tools.includes('patronus_check_result'))
    if (flow === 'queue-backlog') assert(states.includes('pending') && tools.includes('patronus_check_result'))
    if (flow === 'read-redacted') {
      assert(states.includes('dangerous'))
      assert(tools.includes('patronus_read_redacted'))
    }
    return { ...(flow === 'queue-backlog' ? { queueBackpressureVisible: true } : {}), ...(flow === 'read-redacted' ? { exactRedaction: true, unchangedSurroundingContent: true } : {}), ...(flow === 'remote-fail-open' ? { remoteAudit: 'FAILED', degraded: true, failOpen: true } : {}), ...(flow === 'outage-recovery' ? { degradedWarning: true, originalAvailable: true, recovered: true } : {}), root: fixture.root, states, tools, sourceExecutions, modelCalls: fixture.server.requests.length }
  } catch (error) {
    error.evidenceRoot = fixture.root
    error.message += `\nCodex evidence: ${fixture.root}`
    throw error
  } finally { await fixture.close() }
}
