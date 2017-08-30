set -x
curl -s https://api.github.com/repos/sesam-io/sesam/releases/latest | egrep -o '/sesam-io/sesam/releases/download/.*/.*.linux-amd64.tar.gz' | wget --base=http://github.com -i - -O sesam.tar.gz
tar -xf sesam.tar.gz
./sesam -version
