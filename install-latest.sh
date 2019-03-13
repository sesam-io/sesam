set -x
TAG=${SESAM_TAG:-0.0.22}
if [[ $TAG < "1.0.0" ]]
then
  wget -O sesam.tar.gz https://github.com/sesam-io/sesam/releases/download/$TAG/sesam$TAG.linux-amd64.tar.gz
else
  wget -O sesam.tar.gz https://github.com/tombech/sesam-py/releases/download/$TAG/sesam-linux-$TAG.tar.gz
fi
tar -xf sesam.tar.gz
./sesam -version
