#!/bin/bash
# Updating Unbound resources.
# Place this into e.g. /etc/cron.monthly or /etc/cron.weekly
###[ root.hints ]###
curl -o /var/lib/unbound/root.hints.new https://www.internic.net/domain/named.cache
if [[ $? -eq 0 ]]; then
  mv /var/lib/unbound/root.hints /var/lib/unbound/root.hints.bak
  mv /var/lib/unbound/root.hints.new /var/lib/unbound/root.hints
  unbound-checkconf >/dev/null
  if [[ $? -eq 0 ]]; then
    rm /var/lib/unbound/root.hints.bak
    service unbound reload >/dev/null
  else
    echo "Warning: Errors in newly downloaded root.hints file probably due to incomplete download:"
    unbound-checkconf
    mv /var/lib/unbound/root.hints /var/lib/unbound/root.hints.new
    mv /var/lib/unbound/root.hints.bak /var/lib/unbound/root.hints
  fi
else
  echo "Download of unbound root.hints failed!"
fi