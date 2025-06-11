###############################################################################
############## 4b-snortml.sh

### DB running on host (192.168.1.101)
### Snort montoring the traffic on OVS (slow path) via OVS port mirroring
### SQL client running on LP

        HOST                                            ACC                                                           LP               
========================          ==================================================                      =========================

        (DB)                       ACC_PR1_INTF       ACC_PR2_INTF                                          DB Client
    ens801f0v0 --------PR--------- enp0s1f0d4         enps0f1d5   ---- PR --- PHY_PORT_0 ================== ens801f0
    192.168.1.101                     |                   |                                                 192.168.1.102                       
                                      |                   |                                                
                                    ============================
                                            OVS Bridge         
                                    ============================
                                                |     
                                            snort-int 
                                                |
                                            =========
                                              Snort 
                                            =========
###############################################################################



## Checkpoint --> Bring up LNW slow path (OVS) on IPU
# OVS bridge is called 'br-intrnl', port PRs are 'enp0s1f0d4' and 'enp0s1f0d5'


# Configure OVS for port mirroring

# Create a tap interface for Snort to monitor
#ip tuntap add mode tap snort-tap
#ip link set snort-tap up
#ovs-vsctl add-port br-intrnl snort-tap
# Above does not work
# Notes: The main issue is that a tap device in OVS requires a process to be attached to the other side of the interface to establish a carrier.
#   "Open vSwitch has a network device type called "tap". This is intended only for implementing "internal" ports in the OVS userspace switch and should not be used directly.""
#

# Create an internal type interface for Snort to monitor
ovs-vsctl add-port br-intrnl snort-int -- set interface snort-int type=internal
ip link set snort-int up promisc on

# Configure port mirroring (SPAN) to send all traffic to the snort-tap interface
ovs-vsctl -- --id=@m create mirror name=span0 select-all=true \
  -- add bridge br-intrnl mirrors @m \
  -- --id=@snort-int get port snort-int \
  -- set mirror span0 output-port=@snort-int

# Check config
ovs-vsctl list mirror


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

# Verify configuration
snort -c /usr/local/etc/snort/snort.lua --daq-dir=/usr/local/lib/daq/ --plugin-path=/usr/local/lib/snort_extra/ --warn-all

# Run Snort (foreground)
snort -c /usr/local/etc/snort/snort.lua \
  --daq-dir=/usr/local/lib/daq/ \
  --daq afpacket \
  --daq-var buffer_size_mb=1024 \
  -i snort-int \
  -Q \
  --plugin-path=/usr/local/lib/snort_extra/ \
  -A alert_fast \
  -l /var/log/snort


