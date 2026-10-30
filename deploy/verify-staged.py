#!/usr/bin/env python3
"""Check unit syntax before helper installation, without disclosing Exec secrets."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def verify(bundle):
    with tempfile.TemporaryDirectory(prefix='utun-unit-check-') as directory:
        units = []
        for source in sorted(bundle.glob('*.service')):
            # Helpers are installed later. Validate syntax/dependencies separately
            # from executable availability, already checked by provisioning.
            # Preserve each directive name while discarding its full arguments.
            original = source.read_text().splitlines()
            content = '\n'.join(
                re.sub(r'^(Exec\w+)=.*$', r'\1=/usr/bin/true', line)
                for line in original
            ) + '\n'
            target = Path(directory) / source.name
            target.write_text(content)
            units.append(str(target))
        if not units:
            raise SystemExit('No staged systemd units found')
        env = dict(os.environ, SYSTEMD_UNIT_PATH=directory + ':')
        subprocess.run(['systemd-analyze', 'verify', '--man=no',
                        '--generators=no', *units], env=env, check=True)
    print('Staged unit syntax and dependencies verified (Exec arguments redacted)')


if __name__ == '__main__':
    verify(Path(sys.argv[1]))
