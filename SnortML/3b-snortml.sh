###############################################################################
############## 3b-snortml.sh

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
                                            snort-tap 
                                                |
                                            =========
                                              Snort 
                                            =========
###############################################################################


# Install dependencies for SnortML

# Install Python and TensorFlow
dnf install -y python3 python3-pip
pip3 install tensorflow numpy

# Create a directory for our model
mkdir -p ~/snortml_model
cd ~/snortml_model

# Create train_model.py script

cat > train_model.py << 'EOF'
import numpy as np
import tensorflow as tf
from tensorflow import keras

# Define our training data
# Normal HTTP parameter
normal = "id=1234"
# SQL injection attack
attack = "id=1234' OR '1'='1"

# Convert to numpy arrays
normal_np = np.array([ord(c) for c in normal], dtype=np.float32)
attack_np = np.array([ord(c) for c in attack], dtype=np.float32)

# Pad to the same length
max_len = max(len(normal_np), len(attack_np))
normal_padded = np.pad(normal_np, (0, max_len - len(normal_np)))
attack_padded = np.pad(attack_np, (0, max_len - len(attack_np)))

# Create training data
X = np.array([normal_padded, attack_padded])
y = np.array([0, 1])  # 0 for normal, 1 for attack

# Build a simple LSTM model
model = keras.Sequential([
    keras.layers.Embedding(256, 16, input_length=max_len),
    keras.layers.LSTM(8),
    keras.layers.Dense(1, activation='sigmoid')
])

# Compile the model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train the model
model.fit(X, y, epochs=100, verbose=1)

# Save the model
model.save('snort.keras')
print("Model saved to 'snort.model'")
EOF

# Train the model
python3 train_model.py


## Checkpoint --> Bring up LNW (OVS) on ACC
# OVS bridge is called 'br-intrnl', port PRs are 'enp0s1f0d4' and 'enp0s1f0d5'


# Configure OVS for port mirroring

# Create a tap interface for Snort to monitor
ip tuntap add mode tap snort-tap
ip link set snort-tap up

ovs-vsctl add-port br-intrnl snort-tap

# Configure port mirroring (SPAN) to send all traffic to the snort-tap interface
ovs-vsctl -- --id=@m create mirror name=span0 \
  -- add bridge br-intrnl mirrors @m \
  -- --id=@enp0s1f0d4 get port enp0s1f0d4 \
  -- --id=@enp0s1f0d5 get port enp0s1f0d5 \
  -- --id=@snort-tap get port snort-tap \
  -- set mirror span0 select_all=true output-port=@snort-tap


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
        alert tcp any any -> $HOME_NET any (msg:"SQL Injection Attempt - Single Quote"; flow:to_server,established; service:http; http_uri; content:"%27"; sid:1000001; rev:1;)
        alert tcp any any -> $HOME_NET any (msg:"SQL Injection Attempt - Double Quote"; flow:to_server,established; service:http; http_uri; content:"%22"; sid:1000002; rev:1;)
        alert tcp any any -> $HOME_NET any (msg:"SQL Injection Attempt - OR Operator"; flow:to_server,established; service:http; http_uri; content:"OR",nocase; sid:1000003; rev:1;)
        alert tcp any any -> $HOME_NET any (msg:"SQL Injection Attempt - UNION"; flow:to_server,established; service:http; http_uri; content:"UNION",nocase; sid:1000004; rev:1;)
        alert tcp any any -> $HOME_NET any (msg:"SQL Injection Attempt - DROP Statement"; flow:to_server,established; service:http; http_uri; content:"DROP",nocase; sid:1000006; rev:1;)
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
snort -c /usr/local/etc/snort/snort.lua --daq-dir=/usr/local/lib/daq/ \
  --plugin-path=/usr/local/lib/snort_extra/ \
  -i snort-tap \
  --daq afpacket \
  -A alert_fast -l /var/log/snort -v

