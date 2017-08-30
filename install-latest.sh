URL=$( curl -s https://api.github.com/repos/sesam-io/sesam/releases/latest | jq -r '.assets[] | select(.name|endswith("linux-amd64.tar.gz")) | .browser_download_url')
curl -L "$URL" | tar -xz
./sesam -version
