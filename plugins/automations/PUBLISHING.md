# Public Open Source distribution

Source license: Apache-2.0. Each integration has source code, reproducible package
builds, dependency locks, tests, private-install instructions and public package
metadata. This is not evidence of marketplace publication.

## End-user installation targets

| Platform | Intended ready-to-use installation | Current missing publication step |
| --- | --- | --- |
| n8n self-hosted | Install `n8n-nodes-patronus` in Community Nodes, select API key, connect Guard Input | Publish package on npm |
| n8n Cloud | Select an approved community node in the node picker | n8n verification and applicable review requirements |
| Activepieces | Install release `.tgz`, or select the published piece in the catalogue | Public release asset; catalogue review is separate |
| Dify | Install `.difypkg` from the GitHub release or approved marketplace listing | Public release asset and applicable signature/review policy |
| Make | Open the Patronus app installation/invite link, then create a Patronus API connection | Publisher must provision/register the app and share its real link |
| Zapier | Open the Patronus integration invite/listing, connect API key, choose Guard Input | Publisher must register/deploy the integration and share its real link |

End users should not build the repository or assemble Make JSON components. The
Make installer is publisher/fork-maintainer tooling, not the intended end-user
onboarding screen. Do not invent installation links or claim that an unpublished
integration is already in a catalogue.

## Build and release

The `Automation integration release` workflow runs the complete local-test,
dependency-audit and offline-package verification workflow, checks all automation
versions, uploads packages and checksums, then creates a **draft GitHub release**.
It does not publish Make or Zapier automatically. Optional npm publication covers
n8n and Activepieces and uses npm trusted publishing/OIDC with provenance.

One-time owner setup:

1. Create the `automation-releases` GitHub environment and configure its required
   reviewers.
2. Establish ownership of `n8n-nodes-patronus` and
   `@patronus-protect/piece-patronus` on npm. Initial package creation and trusted
   publisher configuration require the package owner's account.
3. Configure npm trusted publishing for repository
   `patronus-protect/patronus-security-cli`, workflow `automation-release.yml` and
   environment `automation-releases`. npm >=11.5.1 is required.
4. Provision the Make app with the included installer, test it in the owner
   account, and obtain its native install/invite link. Deploy the Zapier app using
   its owner account and obtain its native integration invite/listing link.
5. Add the verified install links to the public documentation. Resolve the
   observed API-worker incident and confirm healthy scans before promoting the
   draft as production-ready. Installed-host checks remain necessary for that
   claim; the current validation is local package/SDK validation.

Run the release workflow with the exact source version. npm publication is off
by default. Review the draft and its assets before making it public. These
workflows have not been triggered by the local implementation work.

## API incident, separate from dependency advisories

An earlier synthetic scan on 2026-10-07 returned:

```json
{
  "request_id": "cfcbdc1d-895a-4627-9fcd-bcf353b9e43c",
  "decision": "allow",
  "completion": {
    "state": "degraded",
    "failures": [{ "kind": "WorkerUnavailable", "level": "L3" }]
  }
}
```

The failure message reported HTTP 500 from the backend inference endpoint
`/v2/models/.../infer`. The new automation nodes were not executing in that test;
the call used the existing authenticated API connector. The outer call returned
a scan result rather than an HTTP-500 transport error. This establishes a failed
L3 inference attempt, not its root cause or its current health. Server/inference
logs correlated with the request ID are needed for diagnosis. No further live
checks were run after the user requested local package/SDK tests only.
