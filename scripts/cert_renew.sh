#!/bin/bash
# -*- coding: utf-8 -*-
# Scanner Web Server Certificate Renew

# Look at https://eff-certbot.readthedocs.io/en/latest/using.html#setting-up-automated-renewal
# Better idea from that website:
# MAKE SURE TO REPLACE `<your_username_here>` SECTION!
# SLEEPTIME=$(awk 'BEGIN{srand(); print int(rand()*(3600+1))}'); echo "0 0,12 * * * <your_username_here> sleep $SLEEPTIME && certbot renew --config-dir ~/letsencrypt/config --work-dir ~/letsencrypt/work --logs-dir ~/letsencrypt/logs -q" | sudo tee -a /etc/crontab > /dev/null

certbot renew \
  --config-dir ~/letsencrypt/config \
  --work-dir ~/letsencrypt/work \
  --logs-dir ~/letsencrypt/logs
