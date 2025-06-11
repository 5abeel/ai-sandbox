
# Clear logs
> /var/log/snort/alert_fast.txt

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





# Test no attack (benign) requests
curl --noproxy "*" http://192.168.1.101/vulnerable.php


# Test with a single quote (basic SQL injection attempt)
curl --noproxy "*" http://192.168.1.101/vulnerable.php?id=1%27

# Test with a UNION statement
curl --noproxy "*" http://192.168.1.101/vulnerable.php?id=1%20UNION%20SELECT%201,2,3

# Test with an OR statement
curl --noproxy "*" http://192.168.1.101/vulnerable.php?id=1%20OR%201=1


# Run script (100 requests with 5% attack payloads)
python3 test_sql_injection.py --target http://192.168.1.101/vulnerable.php  --delay 0.5

