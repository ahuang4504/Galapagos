FROM alpine:3.19

RUN apk add --no-cache \
    unbound \
    bind-tools \
    wget \
    && mkdir -p /var/run/unbound \
    && chown unbound:unbound /var/run/unbound

COPY unbound-weak.conf /etc/unbound/unbound-weak.conf
COPY unbound-hardened.conf /etc/unbound/unbound-hardened.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Fetch DNSSEC root trust anchors (needed for Config B hardened mode)
# chown to unbound so Unbound can update the file during key rollover
RUN unbound-anchor -a /etc/unbound/root.key || true \
    && chown unbound:unbound /etc/unbound/root.key

# Fetch root hints (list of root nameservers)
RUN wget -q -O /etc/unbound/root.hints https://www.internic.net/domain/named.root || true

EXPOSE 53/udp 53/tcp

ENTRYPOINT ["/entrypoint.sh"]
