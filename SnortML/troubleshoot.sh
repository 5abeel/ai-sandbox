
4c-ips-mode.sh worked one time, but failed next time

Seems like it is due to AF_PACKET DAQ and the Tx ring queues not getting properly setup/allocated.

Commands tried:


snort -c /usr/local/etc/snort/snort.lua \
  --daq-dir=/usr/local/lib/daq/ \
  --daq afpacket \
  --daq-mode inline \
  --daq-var buffer_size_mb=1024 \
  --daq-var debug=1 \
  --daq-var fanout_type=hash \
  --daq-var use_tx_ring=1 \
  --daq-var use_emergency_tx=1 \
  -i enp0s1f0d5:enp0s1f0d4 \
  -Q -v -z 0




snort -c /usr/local/etc/snort/snort.lua \
  --daq-dir=/usr/local/lib/daq/ \
  --daq afpacket \
  --daq-mode inline \
  --daq-var debug=1 \
  --daq-var buffer_size_mb=512 \
  --daq-var use_emergency_tx=1 \
  -i enp0s1f0d5:enp0s1f0d4 \
  -Q -v -z 0
