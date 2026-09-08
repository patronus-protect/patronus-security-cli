const { callBroker, serveBroker } = await import(process.env.PATRONUS_NATIVE_TEST_ENTRY ?? process.env.PATRONUS_NATIVE_BUNDLE ?? new URL('../dist/patronus.mjs', import.meta.url).href)

const config = JSON.parse(Buffer.from(process.argv[3], 'base64url').toString('utf8'))
if (process.argv[2] === 'daemon') {
  await serveBroker(config)
} else {
  let input = ''
  for await (const chunk of process.stdin) input += chunk
  const request = JSON.parse(input)
  const signal = process.env.PATRONUS_BROKER_ABORT_MS ? AbortSignal.timeout(Number(process.env.PATRONUS_BROKER_ABORT_MS)) : undefined
  process.stdout.write(JSON.stringify(await callBroker(config, request, signal)))
}
