#/bin/sh

for f in `head -1000 /etc/pbgp/65001.cidr` ; do ../bgpctl/bgpctl network add  $f ; done
