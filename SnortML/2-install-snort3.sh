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

ln -s /usr/local/lib/libdaq.so.3 /lib/
ldconfig

## Install Snort3
cd ~/snort-source-files
wget https://github.com/snort3/snort3/archive/refs/tags/3.1.82.0.tar.gz
tar xzf 3.1.82.0.tar.gz
cd snort3-3.1.82.0
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig
make -j $(nproc)
#### if above hangs, just run 'make' (without parallel threads)
make install

ln -s /usr/local/lib/libtcmalloc.so.4 /lib/
ldconfig
