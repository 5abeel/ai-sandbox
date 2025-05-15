# full-bringup with slow-path

# dont need OVS. Snort will be inline and will bridge the traffic
pkill ovs

# Set interfaces in promiscuous mode
ip link set enp0s1f0d5 up promisc on
ip link set enp0s1f0d4 up promisc on

# Disable hardware offloading features that might interfere with Snort
ethtool -K enp0s1f0d5 gro off gso off tso off
ethtool -K enp0s1f0d4 gro off gso off tso off



# Run snort
snort -c /usr/local/etc/snort/snort.lua \
  --daq-dir=/usr/local/lib/daq/ \
  --daq afpacket \
  --daq-mode inline \
  --daq-var buffer_size_mb=1024 \
  -i enp0s1f0d5:enp0s1f0d4 \
  -Q \
  --plugin-path=/usr/local/lib/snort_extra/ \
  -A alert_fast \
  -l /var/log/snort


