#!/bin/sh
set -eu
cd /home/kicba/research_phase1_20261023
test -f phase1/host/evidence/checkpoint.json
export PYTHONDONTWRITEBYTECODE=1
python3 phase1/record_environment.py --output environment_before.json
sudo -n systemctl stop apt-daily.timer apt-daily-upgrade.timer
sudo -n systemctl mask --runtime apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service
for unit in apt-daily.service apt-daily-upgrade.service; do
    if systemctl is-active --quiet "$unit"; then
        printf 'Package operation already active: %s\n' "$unit" >&2
        exit 1
    fi
done
python3 phase1/record_environment.py --output environment_paused.json
sudo -n env PYTHONDONTWRITEBYTECODE=1 python3 phase1/inspect_attachment.py \
    --checkpoint phase1/host/evidence/checkpoint.json \
    --output attachment_pilot_attempt1.json
