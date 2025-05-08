
###############################################################################
############## 3a-snortml.sh

### DB running on ACC (10.10.0.2)
### Snort montoring the 10.10.0.2 interface
### SQL client running on the host


                HOST                                    ACC                             
============================          =========================================

       (SQL Client)                        (Snort & DB)
        ens801f0d3 ----------------------> enp0s1f0d3
        10.10.0.3                           10.10.0.2


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


# Create Snort config to enable SnortML

cat > /usr/local/etc/snort/snort.lua << 'EOF'
-- Basic network configuration
HOME_NET = '10.10.0.2/24'
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


## (Optional): Create a systemd service for Snort
cat > /etc/systemd/system/snort3.service << 'EOF'
[Unit]
Description=Snort3 IDS Daemon Service
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -s 65535 -k none -l /var/log/snort -i ens160 -m 0x1b -u snort
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now snort3

## Notes:

# >> had to re-compile and re-build the libdaq library after all install steps (then I saw the /usr/local/lib/daq/daq_pcap.so file)
#	>> Even with that, I see error with just 
#		snort -c /usr/local/etc/snort/snort.lua -T
#	>> Need to specify the DAQ directory when running Snort
#		snort -c /usr/local/etc/snort/snort.lua -T --daq-dir=/usr/local/lib/daq/


# Verify configuration
snort -c /usr/local/etc/snort/snort.lua --daq-dir=/usr/local/lib/daq/ --plugin-path=/usr/local/lib/snort_extra/ --warn-all

# Run Snort (foreground)
snort -c /usr/local/etc/snort/snort.lua --daq-dir=/usr/local/lib/daq/ -i enp0s1f0d3 -A alert_fast -l /var/log/snort --plugin-path=/usr/local/lib/snort_extra/ -v

