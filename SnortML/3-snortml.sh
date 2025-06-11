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
print("Model saved to 'snort.keras'")
EOF

# Train the model
python3 train_model.py
