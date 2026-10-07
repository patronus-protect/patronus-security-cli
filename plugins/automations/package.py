"""Package built native plugins for private installation; never uploads them."""

import hashlib
import json
import subprocess
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parent
DESTINATION = ROOT / 'dist'


def archive(platform, filename, extensions):
    source = ROOT / platform
    with ZipFile(DESTINATION / filename, 'w', compression=ZIP_DEFLATED) as output:
        for file in sorted(source.rglob('*')):
            if not file.is_file() or '__pycache__' in file.parts or file.suffix not in extensions:
                continue
            relative = file.relative_to(source).as_posix()
            info = ZipInfo(relative, date_time=(2026, 10, 6, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            output.writestr(info, file.read_bytes())
        output.writestr('LICENSE', (source / 'LICENSE').read_bytes())


def main():
    for platform in ['n8n', 'activepieces', 'zapier']:
        if not (ROOT / platform / 'dist').is_dir():
            raise SystemExit('Run npm run build in plugins/automations before packaging.')
        result = subprocess.run(['npm', 'pack', '--json', '--ignore-scripts', '--cache', str(DESTINATION / 'npm-cache'),
                                 '--pack-destination', str(DESTINATION)], cwd=ROOT / platform,
                                capture_output=True, text=True, check=True)
        print(json.loads(result.stdout)[0]['filename'])
    version = json.loads((ROOT / 'package.json').read_text())['version']
    archive('make', f'patronus-make-{version}.zip', {'.json', '.md', '.mjs', '.png'})
    archive('dify', f'patronus-dify-{version}.difypkg', {'.py', '.yaml', '.svg', '.png', '.txt', '.md', '.typed'})
    packages = sorted(file for file in DESTINATION.iterdir() if file.suffix in {'.tgz', '.zip', '.difypkg'} and f'-{version}.' in file.name)
    checksums = '\n'.join(f'{hashlib.sha256(file.read_bytes()).hexdigest()}  {file.name}' for file in packages) + '\n'
    (DESTINATION / 'SHA256SUMS').write_text(checksums)
    print('Packages and SHA256SUMS:', DESTINATION)


if __name__ == '__main__':
    main()
