#!/usr/bin/env python3
"""Verify generated unit syntax without requiring installed deployment binaries."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
root=Path(sys.argv[1] if len(sys.argv)>1 else 'mesh-test')
for bundle in (root/'relay',root/'peer-1'):
    with tempfile.TemporaryDirectory(prefix='utun-units-') as directory:
        units=[]
        for source in bundle.glob('*.service'):
            content=re.sub(r'^(Exec\w+=-?)/\S+',r'\1/usr/bin/true',source.read_text(),flags=re.M)
            target=Path(directory)/source.name;target.write_text(content);units.append(str(target))
        assert units, f'No services in {bundle}'
        env=dict(os.environ,SYSTEMD_UNIT_PATH=directory+':/usr/lib/systemd/system')
        subprocess.run(['systemd-analyze','verify','--man=no','--generators=no',*units],env=env,check=True)
print('Generated systemd unit syntax and dependencies verified')
