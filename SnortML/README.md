# SnortML POC README

All install and configuration steps for SnortML

## Troubleshooting

With the version of Snort3 used here, the `daq` module cannot be specified in the LUA file.
We always see an error even when the DAQ module is properly installed on the system.

Remove the `daq` section from LUA file and specify via command line if required

E.g.:
A file like this will error
```bash
cat > /tmp/test.lua << 'EOF'
HOME_NET = "any"
EXTERNAL_NET = "any"

daq = { module = "afpacket" }

alert_fast = { }
EOF

snort -c /tmp/test.lua --daq-dir=/usr/local/lib/daq/ -T

```

Remove the daq section and pass --daq option in command line instead:

```bash
snort -c /tmp/test.lua --daq-dir=/usr/local/lib/daq/ --daq afpacket -T
```
