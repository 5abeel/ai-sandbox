# Create a user for the Snort service
useradd -r -s /usr/sbin/nologin -M snort

# Create log directory and set permissions
mkdir /var/log/snort
chmod -R 5775 /var/log/snort
chown -R snort:snort /var/log/snort

# Create rules directory
mkdir -p /usr/local/etc/rules


# Download and install the community rules
wget -qO- https://www.snort.org/downloads/community/snort3-community-rules.tar.gz | tar xz -C /usr/local/etc/rules/

