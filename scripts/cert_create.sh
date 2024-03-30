#!/bin/bash
# -*- coding: utf-8 -*-
# Scanner Web Server Certificate Create

# Using https://github.com/infinityofspace/certbot_dns_duckdns

certbot certonly \
  --non-interactive \
  --agree-tos \
  --email <your_email_address> \
  --preferred-challenges dns \
  --authenticator dns-duckdns \
  --dns-duckdns-credentials <path_to_credentials> \
  --dns-duckdns-propagation-seconds 60 \
  -d "<your_domain_name>.duckdns.org" \
  --config-dir ~/letsencrypt/config \
  --work-dir ~/letsencrypt/work \
  --logs-dir ~/letsencrypt/logs
