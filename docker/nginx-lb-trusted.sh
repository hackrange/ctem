#!/bin/sh
# Writes the addresses nginx believes X-Forwarded-For from on the load-balancer listener (:8085), from LB_TRUSTED_IPS
# (comma or space separated IPs or CIDRs, the load balancers' own addresses). Anything else that reaches :8085, such
# as another container on the Docker network, is seen as itself. A catch-all or near catch-all range (an IPv4 prefix
# shorter than /8, an IPv6 prefix shorter than /16) or anything that is not an address is refused and left out.
# Unset on an install that publishes the listener (LB_BIND_IP set), only the bind address's own network (its /24, or
# /64 for IPv6) is trusted, with a warning: the load balancers reach that address over that network, while a
# container on the Docker network or any other host does not get to pick its client address.
set -eu
out=/etc/nginx/lb_trusted.conf
: > "$out"
for ip in $(printf '%s' "${LB_TRUSTED_IPS:-}" | tr ',' ' '); do
  if ! printf '%s' "$ip" | grep -Eq '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$'; then
    echo "lb-trusted: ignoring $ip (not an IP or CIDR)" >&2
    continue
  fi
  case "$ip" in
    */*) bits=$(printf '%s' "${ip#*/}" | sed 's/^0*//'); bits=${bits:-0} ;;
    *) bits=128 ;;
  esac
  case "$ip" in *:*) min=16 ;; *) min=8 ;; esac
  if [ "$bits" -lt "$min" ]; then
    echo "lb-trusted: refusing catch-all $ip" >&2
    continue
  fi
  echo "set_real_ip_from $ip;" >> "$out"
done
if [ ! -s "$out" ]; then
  bind=${LB_BIND_IP:-}
  if [ -n "$bind" ] && [ -z "${LB_TRUSTED_IPS:-}" ]; then
    if [ "$bind" = "0.0.0.0" ] || [ "$bind" = "::" ]; then
      : > "$out"   # listening on every address: no one network to trust, so no peer may set the client address
    elif printf '%s' "$bind" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
      echo "set_real_ip_from ${bind%.*}.0/24;" > "$out"
    elif printf '%s' "$bind" | grep -Eq '^[0-9A-Fa-f:]+$'; then
      echo "set_real_ip_from $bind/64;" > "$out"   # nginx masks the host bits
    fi
    echo "lb-trusted: WARNING LB_TRUSTED_IPS is unset, so :8085 believes X-Forwarded-For from any peer on LB_BIND_IP's network. Set it to your load balancers' addresses." >&2
  else
    echo "lb-trusted: no load balancer addresses, :8085 trusts no forwarded address" >&2
  fi
fi
