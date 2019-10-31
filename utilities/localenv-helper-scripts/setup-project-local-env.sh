#!/bin/bash

# Instructions to use the script to setup a local env to start using the project.
# 1) became root: sudo -i
# 2) create a file w/ the code here under /root dir
# 3) execute it: sh setup-vm.sh

# check for version of ubuntu
version=$(lsb_release -sr)
echo "INFO: version of Ubuntu is $version"

# install all software dependencies
echo '###installing all software dependencies..'
apt update -y || (echo "Error: apt update error" && exit 255)
apt install -y python-pip nfdump libsnappy-dev htop curl unzip || (echo "Error: apt install #1" && exit 255)

case $version in
16.04)
    apt install -y libcurl3 || (echo "Error: apt install libcurl3" && exit 255)
    ;;
18.04)
    apt install -y libcurl4 || (echo "Error: apt install libcurl4" && exit 255)
esac

apt install -y build-essential libssl-dev libffi-dev python-dev zlib1g-dev libbz2-dev automake autoconf || (echo "Error: apt install #2" && exit 255)
apt install -y python3-pip htop || (echo "Error: apt install #3" && exit 255)

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

# RIPENCC BGPdump source code download and compilation
echo '###installing RIPENCC BGPdump ...'
wget https://bitbucket.org/ripencc/bgpdump-hg/get/1.6.0.zip || (echo "Error: downloading RIPENCC BGPdump" && exit 255)
unzip 1.6.0.zip
mv ripencc-bgpdump-hg-6be858c0cc9e ripencc-bgpdump
cd ripencc-bgpdump
sh ./bootstrap.sh
make
cd ..
rm -rf 1.6.0.zip

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

# install all project requirements
echo '###installing Spoofer-IX requirements..'
python -m pip install --upgrade pip setuptools wheel
cd spoofer-ix/
pip install -r requirements.txt || (echo "Error: pip install -r" && exit 255)

# Warn user to remember to set other options manually
echo "!!! REMEMBER:"
echo '*set environment variable to Sendgrid notifications (create your account and generate an APIkey.)'

