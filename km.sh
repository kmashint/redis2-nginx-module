#!/bin/bash

cmd="$1"

[[ -z "$cmd" ]] && { echo "Use $0 configure|make"; exit 1; }

if [[ $cmd == "configure" ]]; then
  pushd ../nginx-1.16.1/

  ./configure --prefix=/usr/local/nginx \
      --with-openssl-opt="no-weak-ssl-ciphers no-ssl3 no-shared -DOPENSSL_NO_HEARTBEATS -fstack-protector-strong" \
      --with-openssl="../openssl-1.1.1h" \
      --with-http_ssl_module \
      --with-stream_ssl_module \
      --add-dynamic-module="../njs/nginx" \
      --add-dynamic-module="../redis2-nginx-module"

  popd
elif [[ $cmd == "make" ]]; then
  pushd ../nginx-1.16.1/

  make

  popd
fi
