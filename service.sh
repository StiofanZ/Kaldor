#!/bin/sh
# Executed under the bootstrap lock with a validated component path.
set -eu
umask 077
cfg=$root/config.json
running() {
 [ -s "$run/pid" ] || return 1
 pid=$(cat "$run/pid")
 case "$pid" in ''|*[!0-9]*) return 1;; esac
 case "$(readlink "/proc/$pid/exe" 2>/dev/null)" in "$root/a"|"$root/b"|"$root/candidate") return 0;; *) return 1;; esac
}
mark=0x02000000/0x02000000
table=189
pref=10891
clean_rules() {
 [ -e "$run/firewall" ] || return 0
 if [ -e "$run/firewall6" ]; then
  read -r iface6 < "$run/firewall6" || return 1
  while ip6tables -t mangle -C PREROUTING -i "$iface6" -j AXPROXY6_LAN 2>/dev/null; do
   ip6tables -t mangle -D PREROUTING -i "$iface6" -j AXPROXY6_LAN || return 1
  done
  if ip6tables -t mangle -S AXPROXY6_LAN >/dev/null 2>&1; then
   ip6tables -t mangle -F AXPROXY6_LAN && ip6tables -t mangle -X AXPROXY6_LAN || return 1
  fi
  if ip -6 rule show | grep -q "^$pref:.*fwmark 0x2000000/0x2000000.*lookup $table"; then
   ip -6 rule del pref "$pref" fwmark "$mark" table "$table" || return 1
  fi
  if ip -6 route show table "$table" proto 222 2>/dev/null | grep -q '^local \(default\|::/0\) dev lo'; then
   ip -6 route del local ::/0 dev lo table "$table" proto 222 || return 1
  fi
  rm -f "$run/firewall6"
 fi
 if [ ! -e "$run/firewall4" ]; then rm -f "$run/firewall"; return 0; fi
 while iptables -t nat -C PREROUTING -j AXPROXY_DNS 2>/dev/null; do
  iptables -t nat -D PREROUTING -j AXPROXY_DNS || return 1
 done
 if iptables -t nat -S AXPROXY_DNS >/dev/null 2>&1; then
  iptables -t nat -F AXPROXY_DNS && iptables -t nat -X AXPROXY_DNS || return 1
 fi
 while iptables -t mangle -C PREROUTING -j AXPROXY_LAN 2>/dev/null; do
  iptables -t mangle -D PREROUTING -j AXPROXY_LAN || return 1
 done
 if iptables -t mangle -S AXPROXY_LAN >/dev/null 2>&1; then
  iptables -t mangle -F AXPROXY_LAN && iptables -t mangle -X AXPROXY_LAN || return 1
 fi
 if ip rule show | grep -q "^$pref:.*fwmark 0x2000000/0x2000000.*lookup $table"; then
  ip rule del pref "$pref" fwmark "$mark" table "$table" || return 1
 fi
 if ip route show table "$table" proto 222 2>/dev/null | grep -q '^local default dev lo'; then
  ip route del local default dev lo proto 222 table "$table" || return 1
 fi
 rm -f "$run/firewall4" "$run/firewall"
}
apply_v6() {
 [ -s "$run/ipv6-rules" ] || return 0
 rules6=$(ip -6 rule show) || { echo "IPv6 policy routing unavailable" >&2; return 1; }
 if printf '%s\n' "$rules6" | grep -q "^$pref:" || [ -n "$(ip -6 route show table "$table" 2>/dev/null)" ] || ip6tables -t mangle -S AXPROXY6_LAN >/dev/null 2>&1; then
  echo 'IPv6 routing resources already in use' >&2; return 1
 fi
 printf '%s\n' "$iface" > "$run/firewall6" || return 1
 ip -6 route add local ::/0 dev lo table "$table" proto 222 || return 1
 ip -6 rule add pref "$pref" fwmark "$mark" table "$table" || return 1
 ip6tables -t mangle -N AXPROXY6_LAN || return 1
 for net in ::/96 ::ffff:0:0/96 ff00::/8; do
  ip6tables -t mangle -A AXPROXY6_LAN -d "$net" -j RETURN || return 1
 done
 v6_targets dns || return 1
 local6=$(ip -6 route show table local) || return 1
 connected6=$(ip -6 route show dev "$iface") || return 1
 for net in fc00::/7 fe80::/10 $(printf '%s\n' "$local6" | awk '$1=="local"{print $2}') $(printf '%s\n' "$connected6" | awk '$1 ~ /:/ && !/ via /{print $1}'); do
  ip6tables -t mangle -A AXPROXY6_LAN -d "$net" -j RETURN || return 1
 done
 v6_targets all || return 1
 ip6tables -t mangle -I PREROUTING 1 -i "$iface" -j AXPROXY6_LAN
}
v6_targets() {
 phase=$1
 while read -r kind selector port; do
  for proto in udp tcp; do
   set -- -p "$proto"
   if [ "$kind" = mac ]; then set -- "$@" -m mac --mac-source "$selector"; else set -- "$@" -s "$selector"; fi
   if [ "$phase" = dns ]; then set -- "$@" --dport 53; fi
   ip6tables -t mangle -A AXPROXY6_LAN "$@" -j TPROXY --on-ip ::1 --on-port "$port" --tproxy-mark "$mark" || return 1
  done
 done < "$run/ipv6-rules"
}
apply_rules() {
 clean_rules || return 1
 devices=$("$1" devices "$2") || return 1
 [ -n "$devices" ] || [ -s "$run/ipv6-rules" ] || return 0
 iface=$(nvram get lan_ifname); lan=$(nvram get lan_ipaddr)
 [ -n "$iface" ] && [ -n "$lan" ] || return 1
 modprobe xt_TPROXY || return 1
 touch "$run/firewall" || return 1
 apply_v6 || return 1
 [ -n "$devices" ] || return 0
 if ip rule show | grep -q "^$pref:" || [ -n "$(ip route show table "$table" 2>/dev/null)" ] || iptables -t mangle -S AXPROXY_LAN >/dev/null 2>&1 || iptables -t nat -S AXPROXY_DNS >/dev/null 2>&1; then
  echo 'Kaldor routing resources already in use' >&2; return 1
 fi
 touch "$run/firewall4" || return 1
 ip route add local default dev lo proto 222 table "$table" || return 1
 ip rule add pref "$pref" fwmark "$mark" table "$table" || return 1
 iptables -t mangle -N AXPROXY_LAN || return 1
 iptables -t mangle -A AXPROXY_LAN ! -i "$iface" -j RETURN || return 1
 # DNS needs reverse NAT so replies retain the DNS server address chosen by the client.
 iptables -t nat -N AXPROXY_DNS || return 1
 for proto in udp tcp; do
  iptables -t mangle -A AXPROXY_LAN -p "$proto" --dport 53 -j RETURN || return 1
  for dev in $devices; do
   iptables -t nat -A AXPROXY_DNS -i "$iface" -s "$dev" -p "$proto" --dport 53 -j DNAT --to-destination "$lan:7893" || return 1
  done
 done
 # Linux 4.4 on this model has no xt_addrtype. Include every local address
 # (including a public WAN address), broadcast and directly attached LAN prefix.
 local_routes=$(ip -4 route show table local) || return 1
 lan_routes=$(ip -4 route show dev "$iface" scope link) || return 1
 destinations=$(printf '%s\n' "$local_routes" | awk '$1 == "local" || $1 == "broadcast" {print $2}')
 connected=$(printf '%s\n' "$lan_routes" | awk '$1 ~ /^[0-9]/ {print $1}')
 for dst in $destinations $connected; do
  iptables -t mangle -A AXPROXY_LAN -d "$dst" -j RETURN || return 1
 done
 for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
  iptables -t mangle -A AXPROXY_LAN -d "$net" -j RETURN || return 1
 done
 for dev in $devices; do
  for proto in tcp udp; do
   iptables -t mangle -A AXPROXY_LAN -s "$dev" -p "$proto" -j TPROXY --on-ip "$lan" --on-port 7893 --tproxy-mark "$mark" || return 1
  done
 done
 iptables -t nat -I PREROUTING 1 -j AXPROXY_DNS || return 1
 iptables -t mangle -I PREROUTING 1 -j AXPROXY_LAN
}
stop() {
 clean_rules || return 1
 if running; then
  kill "$pid" || return 1
  for i in 1 2 3 4 5; do running || break; sleep 1; done
  if running; then kill -KILL "$pid" || return 1; fi
 fi
 rm -f "$run/pid" "$run/ready" "$run/routing-error"
}
# fd 3 reports startup to launch(). The supervisor owns the worker until exit.
supervise() {
 read -r started _ < /proc/uptime
 "$1" serve "$2" "$3" "$4" "$run/ready" 3>&- &
 child=$!
 echo "$child" > "$run/pid"
 for tick in 0 1 2 3 4 5 6; do
  if [ -s "$run/ready" ] && running; then
   read -r ready_at _ < /proc/uptime
   echo "worker ready: pid=$child launch_uptime=$started ready_uptime=$ready_at"
   echo ready >&3
   exec 3>&-
   code=0
   wait "$child" || code=$?
   echo "worker exited: status=$code"
   "$AXPROXY_CTL" reaped "$child"
   return
  fi
  if ! kill -0 "$child" 2>/dev/null; then
   code=0
   wait "$child" || code=$?
   echo "worker exited before readiness: status=$code"
   return 1
  fi
  [ "$tick" = 6 ] || sleep 1
 done
 echo "worker readiness timed out"
 kill -KILL "$child" 2>/dev/null || :
 wait "$child" 2>/dev/null || :
 return 1
}
launch() {
 "$1" check "$2" || return 1
 "$1" enabled "$2" 2>/dev/null || return 0
 lan=$(nvram get lan_ipaddr) && iface=$(nvram get lan_ifname) || return 1
 [ -n "$lan" ] && [ -n "$iface" ] || return 1
 rm -f "$run/ready" "$run/ipv6-rules" || return 1
 # Closing fd 3 releases the reader as soon as the listeners are ready.
 result=$(
  (
   exec 3>&1 9>&- </dev/null >"$run/service.log" 2>&1
   supervise "$1" "$2" "$lan" "$iface"
  ) &
 )
 if [ "$result" = ready ] && running && apply_rules "$1" "$2"; then return 0; fi
 stop
 return 1
}
case "$1" in
 configure)
  request=$("$bin" release-request "$2" "$run" 9>&-) || exit 1
  [ "$request" != queued ] || exit 0
  "$bin" merge "$2" "$cfg" > "$root/config.new" || { rm -f "$root/config.new"; exit 1; }
  stop
  if launch "$bin" "$root/config.new" && mv "$root/config.new" "$cfg"; then exit 0; fi
  stop; rm -f "$root/config.new"; launch "$bin" "$cfg"; exit 1;;
 start)
  code=0
  stop && launch "$bin" "$cfg" || code=$?
  if [ "$code" = 0 ] && [ "$bin" = "$root/candidate" ]; then
   "$bin" mark-candidate "$root" || code=$?
  fi
  if [ "$code" = 0 ] && [ -e "$root/prune.pending" ]; then
   # Pin the candidate inode before the immutable firmware loader renames it.
   # Its cleanup worker waits for the install transaction to release fd 9.
   exec 4<"$bin"
   /proc/self/fd/4 prune-installed "$root" "$run" 9>&- </dev/null >>"$run/service.log" 2>&1 &
   exec 4<&-
  fi
  logger -t kaldor "component start: status=$code" || :
  exit "$code";;
 stop) stop;;
 reaped)
  if [ "$(cat "$run/pid" 2>/dev/null || true)" = "$2" ] && ! running; then
   clean_rules
   rm -f "$run/pid" "$run/ready" "$run/routing-error"
  fi;;
 firewall)
  if running; then
   apply_rules "$bin" "$cfg" || { touch "$run/routing-error"; clean_rules; exit 1; }
   rm -f "$run/routing-error"
  else clean_rules; fi;;
 view) "$bin" view "$cfg";;
 status) if [ -e "$run/routing-error" ]; then echo degraded; elif running && [ -s "$run/ready" ]; then echo running; else echo stopped; fi;;
 page) "$bin" page;;
 *) exit 2;;
esac
