set -x
TAG=${SESAM_TAG:-0.0.18}
wget -O sesam.tar.gz https://github.com/sesam-io/sesam/releases/download/$TAG/sesam$TAG.linux-amd64.tar.gz
tar -xf sesam.tar.gz
./sesam -version
