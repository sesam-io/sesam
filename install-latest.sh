set -x
wget -O sesam.tar.gz https://github.com/sesam-io/sesam/releases/download/0.0.17/sesam0.0.17.linux-amd64.tar.gz
tar -xf sesam.tar.gz
./sesam -version
