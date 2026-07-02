# Firewall image for the name-level-allowlist egress boundary: squid (ssl-bump) +
# dnsmasq (static resolver) + the iptables/ipset backstop, plus the extracted
# firewall libraries. The egress-floor probe (tests/smoke/firewall-egress-probe.sh)
# runs against this image to prove block/allow decisions and the tamper-evident log.
FROM debian:stable-slim@sha256:ee12ffb55625b99d62837a72f037d9b2f18fd0c787a89c2b9a4f09666c48776c

# dnsutils (dig): the resolver + the DNS self-tests; iproute2 (ip): the host-gateway
# probe; procps (sysctl, pkill/pgrep): conntrack hardening + the dnsmasq drain in the
# refresh loop — all exercised by init-firewall.bash at every boot.
RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  git \
  iptables \
  ipset \
  grepcidr \
  jq \
  dnsmasq \
  dnsutils \
  iproute2 \
  procps \
  squid-openssl \
  ssl-cert \
  openssl \
  python3 \
  && rm -rf /var/lib/apt/lists/*

# Throwaway CA for squid ssl_bump, trusted only inside this container: it lets squid
# inspect HTTPS to enforce the per-method (GET/HEAD vs POST) read-only tier. Also
# initialize the on-disk cert cache (ssl_db) squid mints per-host certs into.
RUN mkdir -p /etc/squid/ssl_cert && \
  openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
  -subj "/C=US/ST=Sandbox/L=Sandbox/O=agent-sandbox/CN=agent-sandbox-proxy-ca" \
  -keyout /etc/squid/ssl_cert/ca-key.pem \
  -out /etc/squid/ssl_cert/ca-cert.pem && \
  cat /etc/squid/ssl_cert/ca-key.pem /etc/squid/ssl_cert/ca-cert.pem \
  >/etc/squid/ssl_cert/ca-bundle.pem && \
  /usr/lib/squid/security_file_certgen -c -s /var/spool/squid/ssl_db -M 4MB && \
  cp /etc/squid/ssl_cert/ca-cert.pem /usr/local/share/ca-certificates/sandbox-proxy-ca.crt && \
  update-ca-certificates && \
  chown -R root:proxy /etc/squid/ssl_cert /var/spool/squid/ssl_db && \
  chmod 640 /etc/squid/ssl_cert/ca-key.pem /etc/squid/ssl_cert/ca-bundle.pem && \
  chmod 444 /etc/squid/ssl_cert/ca-cert.pem

# Bake squid's log dir proxy-owned 750 so squid can append access.log (the egress log)
# with no privileged runtime chmod.
RUN mkdir -p /var/log/squid && chmod 750 /var/log/squid && chown proxy:proxy /var/log/squid

# The firewall library layer. firewall-lib.bash sources its siblings by directory, so
# they must all land together on PATH.
COPY firewall-lib.bash ip-validation.bash dns-resolver.bash squid-config.bash \
  egress-rules.bash conntrack.bash trace.bash trace-events.bash launch-trace.bash \
  launch-marks.bash json.bash init-firewall.bash hardener-entrypoint.bash \
  audit_sink.py /usr/local/bin/
