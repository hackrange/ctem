#!/bin/sh
# Writes the addresses nginx believes X-Forwarded-For from on the load-balancer listener (:8085), from LB_TRUSTED_IPS
# (comma or space separated IPs or CIDRs, the load balancers' own addresses). Anything else that reaches :8085, such
# as another container on the Docker network, is seen as itself. A catch-all range (0.0.0.0/0, ::/0) or anything that
# is not an address is refused and left out. Unset on an install that publishes the listener (LB_BIND_IP set), every
# peer is still trusted as before, with a warning, so an upgrade never makes all users look like the load balancer.
set -eu
out=/etc/nginx/lb_trusted.conf
: > "$out"
for ip in $(printf '%s' "${LB_TRUSTED_IPS:-}" | tr ',' ' '); do
  case "$ip" in
    0.0.0.0/0|::/0|0/0) echo "lb-trusted: refusing catch-all $ip" >&2; continue ;;
  esac
  if printf '%s' "$ip" | grep -Eq '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$'; then
    echo "set_real_ip_from $ip;" >> "$out"
  else
    echo "lb-trusted: ignoring $ip (not an IP or CIDR)" >&2
  fi
done
if [ ! -s "$out" ]; then
  if [ -n "${LB_BIND_IP:-}" ] && [ -z "${LB_TRUSTED_IPS:-}" ]; then
    echo "set_real_ip_from 0.0.0.0/0;" > "$out"
    echo "lb-trusted: WARNING LB_TRUSTED_IPS is unset, so :8085 believes X-Forwarded-For from any peer that reaches it. Set it to your load balancers' addresses." >&2
  else
    echo "lb-trusted: no load balancer addresses, :8085 trusts no forwarded address" >&2
  fi
fi
