#!/bin/bash

# Instructions to use the script to setup a local env to start using the project.
# 1) became root: sudo -i
# 2) create a file w/ the code here under /root dir
# 3) execute it: sh setup-vm.sh

# install all software dependencies
echo '###installing all software dependencies..'
apt update -y || (echo "Error: apt update before python pip" && exit 255)
apt install -y python-pip nfdump libsnappy-dev htop || (echo "Error: apt install" && exit 255)
apt install -y build-essential libssl-dev libffi-dev python-dev zlib1g-dev libbz2-dev unzip libcurl3 automake autoconf || (echo "Error: apt install" && exit 255)
apt install -y python3-pip htop || (echo "Error: apt install" && exit 255)

pip3 install scrapy --upgrade
pip3 install service_identity

echo '###installing GIT-LFS dependencies..'
apt install -y software-properties-common
add-apt-repository ppa:git-core/ppa -y
curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
apt install -y git-lfs
git lfs install

# do clone from Github repository
echo '###cloning from Github repository..'
git lfs clone https://github.com/spoofer-ix/spoofer-ix.git || (echo "Error: git clone" && exit 255)

# install and setup Apache Avro
echo '###installing Apache Avro..'
wget http://ftp.unicamp.br/pub/apache/avro/avro-1.9.0/py/avro-1.9.0.tar.gz || (echo "Error: wget avro" && exit 255)
tar xvf avro-1.9.0.tar.gz
cd avro-1.9.0
python setup.py install || (echo "Error: avro install" && exit 255)
cd ..


# RIPENCC BGPdump source code download and compilation
echo '###installing RIPENCC BGPdump ...'
wget https://bitbucket.org/ripencc/bgpdump/get/fa473c477531.zip
unzip fa473c477531.zip
mv ripencc-bgpdump-fa473c477531 ripencc-bgpdump
cd ripencc-bgpdump
sh ./bootstrap.sh
make
cd ..
rm -rf fa473c477531.zip

echo '# installing wandio ...'
curl -O https://research.wand.net.nz/software/wandio/wandio-1.0.4.tar.gz
tar zxf wandio-1.0.4.tar.gz
cd wandio-1.0.4/
./configure
make
sudo make install
sudo ldconfig
cd ..
rm -rf wandio-1.0.4.tar.gz

#########
# install Perl depedencies
#########
cpan -i install Net::Patricia
cpan -i install Parallel::ForkManager

# cleaning temporary files downloaded
echo '###cleaning temp downloaded files..'
rm -rf avro-1.9.0.tar.gz avro-1.9.0/ || (echo "Error: deleting files downloaded" && exit 255)

# install all project requirements
echo '###installing Spoofer-IX requirements..'
python -m pip install --upgrade pip setuptools wheel
cd spoofer-ix/
pip install -r requirements.txt || (echo "Error: pip install -r" && exit 255)

# Warn user to remember to set other options manually
echo "!!! REMEMBER:"
echo '*set environment variable to Sendgrid notifications (create your account and generate an APIkey.)'

