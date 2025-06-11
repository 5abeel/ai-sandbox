# Install required dependencies for Snort3 on RL9.x

# Install EPEL and enable CRB repositories
dnf install epel-release
dnf config-manager --enable crb

# Install required build tools and dependencies
dnf install -y cmake gcc-c++ bison flex libtool nghttp2 libnghttp2-devel \
    libpcap-devel pcre-devel openssl-devel libdnet-devel \
    libtirpc-devel git gcc-c++ libunwind-devel cmake hwloc-devel \
    luajit-devel xz-devel libnfnetlink-devel libmnl-devel \
    libnetfilter_queue-devel uuid-devel 

# Following deps needed for tcmalloc
dnf install -y google-perftools google-perftools-devel

## libsafec-devel is not available as dnf package 
## and is a dependency for software like ipmctl. 
## Build from source

git clone https://github.com/rurban/safeclib.git
cd safeclib
./build-aux/autogen.sh
./configure
make
sudo make install
