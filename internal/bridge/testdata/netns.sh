#!/bin/bash
# Invoked inside unshare -Urn: all links/rules/sysctls below are namespace-local.
set -Eeuo pipefail
[[ $(id -u) == 0 ]] || exit 1
root=$(mktemp -d)
pids=()
cleanup() { for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; rm -rf "$root"; }
trap cleanup EXIT
ip link add switch0 type bridge
ip link set switch0 up
index=10
for name in relay client exit; do
  unshare -n sleep 120 &
  pid=$!;pids+=("$pid")
  # Wait for the child to enter its new namespace (not just fork).
  for attempt in {1..100}; do
    if [[ $(readlink "/proc/$pid/ns/net") != $(readlink /proc/self/ns/net) ]]; then break; fi
    sleep 0.01
  done
  printf -v "${name}_pid" '%s' "$pid"
  ip link add "${name}0" type veth peer name eth0
  ip link set eth0 netns "$pid"
  ip link set "${name}0" master switch0
  ip link set "${name}0" up
  nsenter -t "$pid" -n ip link set lo up
  nsenter -t "$pid" -n ip link set eth0 up
  nsenter -t "$pid" -n ip addr add "203.0.113.$index/24" dev eth0
  index=$((index+1))
done
nsenter -t "$exit_pid" -n ip addr add 203.0.113.22/24 dev eth0
mkdir "$root/bin"
printf '#!/bin/sh\nexit 0\n' > "$root/bin/systemctl"
chmod 700 "$root/bin/systemctl"
export PATH="$root/bin:$PATH"
python3 - "$1" "$2" "$root" <<'PY'
import pathlib,sys
root=pathlib.Path(sys.argv[3])
for name,src in zip(['first','second'],sys.argv[1:3]):
 target='203.0.113.12' if name=='first' else '203.0.113.22'
 s=pathlib.Path(src).read_text().replace("EXIT_IP='198.51.100.20'","EXIT_IP='"+target+"'").replace("EXIT_IP='198.51.100.21'","EXIT_IP='"+target+"'")
 s=s.replace('STATE=/var/lib/kitsune-bridge','STATE='+str(root/'state')).replace('APPLY=/usr/local/sbin/kitsune-bridge-apply','APPLY='+str(root/'helper')).replace('UNIT=/etc/systemd/system/kitsune-bridge.service','UNIT='+str(root/'unit'))
 (root/name).write_text(s)
PY
# Two TCP and UDP listeners to exercise a real port update.
nsenter -t "$exit_pid" -n python3 - "$root/ready" <<'PY' &
import socket,threading,time,sys,pathlib
listeners=[]
def tcp(s):
 while True:
  c,peer=s.accept();c.sendall(peer[0].encode()+b'|'+c.recv(64));c.close()
def udp(s):
 while True:
  data,peer=s.recvfrom(64);s.sendto(peer[0].encode()+b'|'+data,peer)
for port in [18443,18444]:
 t=socket.socket();t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);t.bind(('0.0.0.0',port));t.listen();listeners.append(t)
 threading.Thread(target=tcp,args=(t,),daemon=True).start()
 for address in ['203.0.113.12','203.0.113.22']:
  u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind((address,port));listeners.append(u)
  threading.Thread(target=udp,args=(u,),daemon=True).start()
pathlib.Path(sys.argv[1]).touch();time.sleep(110)
PY
server_pid=$!;pids+=("$server_pid")
for attempt in {1..100}; do [[ ! -f "$root/ready" ]] || break; sleep 0.02; done
relay() { nsenter -t "$relay_pid" -n "$@"; }
relay nft add table ip unrelated
relay nft 'add chain ip unrelated input { type filter hook input priority 5; policy accept; }'
relay nft list table ip unrelated > "$root/foreign.before"
probe() {
  nsenter -t "$client_pid" -n python3 - "$1" <<'PY'
import socket,sys
port=int(sys.argv[1])
for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
 s=socket.socket(socket.AF_INET,kind);s.settimeout(3);s.connect(('203.0.113.10',port));s.send(b'hello');data=s.recv(64);s.close()
 assert data==b'203.0.113.10|hello',data
PY
}
relay bash "$root/first"
probe 18443
relay bash "$root/second"
probe 18444
relay bash "$root/second"
probe 18444
# A kernel-rejected transaction must leave the working table intact.
cat > "$root/bad.nft" <<'BAD'
delete table ip kitsune_bridge
add table ip kitsune_bridge
add rule ip kitsune_bridge missing_chain counter accept
BAD
if relay nft --file "$root/bad.nft" > "$root/expected-error" 2>&1; then exit 1; fi
probe 18444
# Validate that an unrelated routed destination is NOT forwarded by the bridge.
nsenter -t "$exit_pid" -n ip addr add 198.51.100.77/32 dev lo
nsenter -t "$client_pid" -n ip route add 198.51.100.77/32 via 203.0.113.10
nsenter -t "$client_pid" -n python3 - <<'PY'
import socket
s=socket.socket();s.settimeout(1)
try:s.connect(('198.51.100.77',18444))
except (TimeoutError,OSError):pass
else:raise AssertionError('unrelated forwarding allowed')
finally:s.close()
PY
relay bash "$root/helper" stop
relay bash "$root/helper" start
probe 18444
# Simulate lost live rules after reboot; the persisted helper must restore them.
relay nft delete table ip kitsune_bridge
relay sysctl -qw net.ipv4.ip_forward=0
relay bash "$root/helper" start
probe 18444
relay bash "$root/second" remove
relay nft list table ip unrelated > "$root/foreign.after"
cmp "$root/foreign.before" "$root/foreign.after"
if relay nft list table ip kitsune_bridge >/dev/null 2>&1; then exit 1; fi
echo 'PASS: real nftables TCP/UDP DNAT+SNAT, update, repeat, stop/start, reboot restoration, restricted forwarding, foreign-table preservation, removal'
