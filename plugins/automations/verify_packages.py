"""Offline installation and SDK registration checks for the shipped packages."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parent


def main():
    version = json.loads((ROOT / 'package.json').read_text())['version']
    with tempfile.TemporaryDirectory(prefix='patronus-package-smoke-') as location:
        project = Path(location)
        (project / 'package.json').write_text(json.dumps({'name': 'patronus-package-smoke', 'version': '0.0.0', 'private': True}))
        archives = [ROOT / 'dist' / f'{name}-{version}.tgz' for name in [
            'n8n-nodes-patronus', 'patronus-protect-piece-patronus', 'patronus-zapier']]
        # n8n supplies n8n-workflow to community nodes at runtime, so peer dependencies are
        # not installed here and only that host module is exposed via NODE_PATH.
        result = subprocess.run(['npm', 'install', '--offline', '--legacy-peer-deps', '--ignore-scripts', '--no-audit', *map(str, archives)],
                                cwd=project, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr[-2000:])
        host = project / 'n8n-host'
        host.mkdir()
        (host / 'n8n-workflow').symlink_to(ROOT / 'node_modules' / 'n8n-workflow', target_is_directory=True)
        subprocess.run(['node', '-e', """
const {createRequire}=require('node:module'); const fs=require('node:fs'),path=require('node:path');
const n=require('n8n-nodes-patronus');
if(new n.Patronus().description.properties[0].default!=='guard') throw Error('n8n guard missing');
const p=require('@patronus-protect/piece-patronus').patronus;
if(!p.getAction('guard_input')) throw Error('piece guard missing');
const z=require('patronus-zapier'); if(!z.creates.guard_input) throw Error('Zapier guard missing');
const app=createRequire(require.resolve('patronus-zapier'));
const core=createRequire(app.resolve('zapier-platform-core'));
let directory=path.dirname(core.resolve('form-data'));
while(!fs.existsSync(path.join(directory,'package.json'))) directory=path.dirname(directory);
const version=JSON.parse(fs.readFileSync(path.join(directory,'package.json'))).version;
if(version!=='4.0.6') throw Error('Unpatched installed form-data '+version);
console.log('All npm guards load from isolated offline installation; form-data='+version);
"""], cwd=project, check=True, env={**os.environ, 'NODE_PATH': str(host)})
    with ZipFile(ROOT / 'dist' / f'patronus-dify-{version}.difypkg') as archive:
        assert archive.testzip() is None
        with tempfile.TemporaryDirectory(prefix='patronus-dify-smoke-') as location:
            archive.extractall(location)
            subprocess.run([sys.executable, '-c', '''
from dify_plugin import DifyPluginEnv
from dify_plugin.core.plugin_registration import PluginRegistration
r=PluginRegistration(DifyPluginEnv())
assert any(t.identity.name=='guard_input' for t in r.tools_configuration[0].tools)
print('Packaged Dify guard registers with its SDK')
'''], cwd=location, check=True)
    with ZipFile(ROOT / 'dist' / f'patronus-make-{version}.zip') as archive:
        assert archive.testzip() is None
        definition = json.loads(archive.read('modules/guard_input.communication.json'))
        assert definition[-1]['response']['output']['text'] == '{{parameters.content}}'
        # The documented flow unpacks the archive and runs the installer from it.
        with tempfile.TemporaryDirectory(prefix='patronus-make-smoke-') as location:
            archive.extractall(location)
            subprocess.run(['node', 'install.mjs', '--zone', 'eu1.make.com'], cwd=location, check=True, capture_output=True)
        print('Packaged Make guard definition verified; installer dry run works from the archive')


if __name__ == '__main__':
    main()
