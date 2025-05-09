# Install Snort3

mkdir -p ~/snort-source-files
cd ~/snort-source-files

## libdaq is a required dependency
git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make
make install

ln -s /usr/local/lib/libtcmalloc.so.4 /lib/
ln -s /usr/local/lib/libdaq.so.3 /lib/
echo "/usr/local/lib/" > /etc/ld.so.conf.d/libdaq3.conf
ldconfig

## Install Snort3
cd ~/snort-source-files
wget https://github.com/snort3/snort3/archive/refs/tags/3.1.82.0.tar.gz
tar xzf 3.1.82.0.tar.gz
cd snort3-3.1.82.0
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig
## make -j $(nproc) ## this usually hangs (atleast it does, on RL9.x). Run single thread instead
make
make install

ln -s /usr/local/lib/libtcmalloc.so.4 /lib/
ldconfig

# Verify the installation
snort -V

# Install Snort DAQ (Data Acquisition Library)
cd ~/snort-source-files
git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make
make install
ldconfig


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
