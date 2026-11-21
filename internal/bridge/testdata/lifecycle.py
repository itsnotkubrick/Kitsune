"""Execute the real installer with isolated command doubles; never alter host networking."""
import json, os, pathlib, subprocess, sys, tempfile
source, updated = map(pathlib.Path, sys.argv[1:])
root = pathlib.Path(tempfile.mkdtemp(prefix='bridge-lifecycle-'))
bin = root / 'bin'; bin.mkdir()
state = root / 'state'; helper = root / 'helper'; unit = root / 'unit'
def stub(name, body):
    p=bin/name; p.write_text(body); p.chmod(0o700)
stub('id', '#!/bin/sh\necho 0\n')
stub('stat', '#!/bin/sh\necho 0:700\n')
stub('ip', '#!/bin/sh\necho "198.51.100.20 dev eth0 src 203.0.113.10"\n')
stub('ss', '#!/bin/sh\nif [ "${BUSY:-}" = 1 ]; then echo LISTEN; fi\n')
stub('sysctl', '''#!/usr/bin/env python3
import os,pathlib,sys
p=pathlib.Path(os.environ['TESTROOT'])/'forward'
if '-n' in sys.argv: print(p.read_text() if p.exists() else '0')
else:
 if os.environ.get('FAILSYSCTL')=='1' and sys.argv[-1].endswith('=1'):sys.exit(1)
 p.write_text(sys.argv[-1].split('=')[-1])
''')
stub('nft', '''#!/usr/bin/env python3
import json,os,pathlib,sys
r=pathlib.Path(os.environ['TESTROOT']); p=r/'table'; a=sys.argv[1:]
with (r/'calls').open('a') as f:f.write(json.dumps(a)+'\\n')
if a==['-j','list','ruleset']:
 items=[{'table':{'family':'ip','name':'unrelated'}}]
 if p.exists():items.append({'table':{'family':'ip','name':'kitsune_bridge'}})
 if os.environ.get('FOREIGN')=='1':items.append({'chain':{'family':'ip','table':'docker','hook':'forward'}})
 print(json.dumps({'nftables':items}));sys.exit(0)
if 'list' in a:
 if not p.exists():sys.exit(1)
 if '-j' in a:print(json.dumps({'nftables':[{'table':{'family':'ip','name':'kitsune_bridge','comment':'Kitsune bridge v2'}}]}))
 else:print(p.read_text())
 sys.exit(0)
if a[:2]==['delete','table']:p.unlink();sys.exit(0)
if '--file' in a:
 text=pathlib.Path(a[a.index('--file')+1]).read_text()
 assert 'flush ruleset' not in text
 assert 'table ip kitsune_bridge' in text
 assert 'policy drop' in text
 assert 'ct original ip daddr 203.0.113.10' in text
 assert 'iifname "eth0" ip daddr 203.0.113.10' in text
 if '--check' in a:
  if os.environ.get('FAILCHECK')=='1':sys.exit(1)
  sys.exit(0)
 if os.environ.get('FAILNFT')=='1' and a[-1].endswith('new.nft'):sys.exit(1)
 p.write_text('\\n'.join(l for l in text.splitlines() if not l.startswith('delete table'))+'\\n');sys.exit(0)
sys.exit('unexpected nft invocation '+str(a))
''')
stub('systemctl', '''#!/usr/bin/env python3
import os,pathlib,sys,subprocess
r=pathlib.Path(os.environ['TESTROOT']);a=sys.argv[1:]
if a and a[0]=='is-enabled':sys.exit(0 if (r/'enabled').exists() else 1)
if a[:2]==['enable','--now']:
 (r/'enabled').touch()
 if os.environ.get('FAILSYSTEMD')=='1':sys.exit(1)
 if not (r/'running').exists():
  result=subprocess.run(['bash',str(r/'helper'),'start'],capture_output=True)
  if result.returncode:sys.stderr.buffer.write(result.stderr);sys.exit(result.returncode)
  (r/'running').touch()
if a and a[0]=='disable':
 (r/'enabled').unlink(missing_ok=True)
 if '--now' in a:(r/'running').unlink(missing_ok=True)
''')
env=dict(os.environ,PATH=str(bin)+':'+os.environ['PATH'],TESTROOT=str(root))
def prepare(path, name):
    s=path.read_text().replace('STATE=/var/lib/kitsune-bridge','STATE='+str(state)).replace('APPLY=/usr/local/sbin/kitsune-bridge-apply','APPLY='+str(helper)).replace('UNIT=/etc/systemd/system/kitsune-bridge.service','UNIT='+str(unit))
    p=root/name;p.write_text(s);return p
first=prepare(source,'install.sh');second=prepare(updated,'update.sh')
def run(path,*args,fail=False,**flags):
    result=subprocess.run(['bash',str(path),*args],env=dict(env,**flags),capture_output=True,text=True,timeout=20)
    assert (result.returncode!=0)==fail,(result.returncode,result.stdout,result.stderr)
    return result
paste_dir = root / 'paste'
paste_dir.mkdir()
result = subprocess.run(['bash', '-s'], input=first.read_text(), text=True,
                        env=dict(env, TMPDIR=str(paste_dir)), capture_output=True, timeout=20)
assert result.returncode == 0, (result.stdout, result.stderr)
assert not list(paste_dir.iterdir()), 'paste wrapper left its temporary file behind'
assert helper.read_text().startswith('#!/bin/bash\n# Kitsune bridge v2')
assert (root/'table').exists() and helper.exists() and unit.exists()
assert 'tcp dport 443' in (root/'table').read_text()
old=(root/'table').read_text();oldhelper=helper.read_text()
for flags in [{'FAILCHECK':'1'},{'FAILNFT':'1'},{'FAILSYSCTL':'1'},{'FAILSYSTEMD':'1'}]:
    run(second,fail=True,**flags)
    assert (root/'table').read_text().strip()==old.strip(),flags
    assert helper.read_text()==oldhelper
run(second)
assert 'tcp dport 8443' in (root/'table').read_text() and 'tcp dport 443 ' not in (root/'table').read_text()
assert '198.51.100.21' in (root/'table').read_text()
run(second)  # active oneshot: installer still reapplies synchronously
(root/'table').unlink();(root/'running').unlink();(root/'forward').write_text('0')
(state/'pending').touch() # stale marker from an interrupted installer
run(helper,'start')  # simulated reboot: retained files, no live rules/processes
assert (root/'table').exists() and (root/'forward').read_text()=='1'
run(second,fail=True,BUSY='1')
run(second,fail=True,FOREIGN='1')
run(helper,'remove',FOREIGN='1') # removal must remain possible after foreign services appear
assert not (root/'table').exists() and not helper.exists() and not unit.exists()
# Failure on a fresh installation restores forwarding and removes partial files/rules.
import shutil
shutil.rmtree(state);(root/'forward').write_text('0')
run(first,fail=True,FAILSYSTEMD='1')
assert not (root/'table').exists() and not helper.exists() and not unit.exists()
assert (root/'forward').read_text()=='0'
assert not (root/'enabled').exists()
print('PASS: install, update/changed exit and port, repeat, reboot model, removal, conflicts, atomic failure, rollback')
shutil.rmtree(root)
