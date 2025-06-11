# full-bringup with slow-path

# Create Snort config to enable SnortML

cat > /usr/local/etc/snort/snort.lua << 'EOF'
-- Basic network configuration
-- Set HOME_NET to the network of the protected segment (the DB server network)
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Include default configurations
dofile('/usr/local/etc/snort/snort_defaults.lua')

-- Configure SnortML engine
snort_ml_engine = {
    models = {
        {
            name = 'sql_injection_model',
            path = '/root/snortml_model/snort.keras',
        }
    }
}

-- Configure SnortML inspector
snort_ml = {
    classifiers = {
        {
            name = 'sql_injection_classifier',
            model = 'sql_injection_model',
            threshold = 0.5,
        }
    }
}

-- Add traditional SQL injection rules
ips = {
    rules = [[
        pass arp any any -> any any (msg:"Allow ARP traffic"; sid:1000000; rev:1;)
        alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt - Single Quote"; content:"%27"; sid:1000001; rev:1;)
        alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt - Double Quote"; content:"%22"; sid:1000002; rev:1;)
        alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt - OR Operator"; content:"OR",nocase; sid:1000003; rev:1;)
        alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt - UNION"; content:"UNION",nocase; sid:1000004; rev:1;)
        alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt - DROP Statement"; content:"DROP",nocase; sid:1000006; rev:1;)
    ]],
    variables = default_variables
}

-- Configure outputs
alert_fast = {
    file = true,
    packet = true,
    limit = 100,
}
EOF

# validate the .lua config
snort -c /usr/local/etc/snort/snort.lua \
  --daq-dir=/usr/local/lib/daq/ \
  --daq afpacket \
  --daq-mode inline \
  -i enp0s1f0d5:enp0s1f0d4 \
  -Q \
  -T


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


