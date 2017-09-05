set -x
wget -O sesam.tar.gz https://github.com/sesam-io/sesam/releases/download/0.0.18/sesam0.0.18.linux-amd64.tar.gz
tar -xf sesam.tar.gz
./sesam -version
