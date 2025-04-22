#!/bin/sh

set -e # Exit if any command fails

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT # Ensure temporary directory is removed on script exit

v2dat_dir=./

geodat_update() {
    curl --connect-timeout 5 -m 60 -kfSL -o "$TMPDIR/geoip.dat" "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"

    curl --connect-timeout 5 -m 60 -kfSL -o "$TMPDIR/geosite.dat" "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"

    \cp -a "$TMPDIR"/geoip.dat "$TMPDIR"/geosite.dat $v2dat_dir
}

# Unpack and process the data
v2dat_dump() {
    mkdir -p "$v2dat_dir/rules/"

    "./v2dat" unpack geoip -o "$v2dat_dir/rules/" -f cn -f private -f cloudflare "$v2dat_dir/geoip.dat"
    "./v2dat" unpack geosite -o "$v2dat_dir/rules/" -f apple-cn -f cn -f google-cn -f category-games@cn -f tracker -f category-pt "$v2dat_dir/geosite.dat"

}

update_local_ptr() {
    curl --connect-timeout 5 -m 60 -kfSL -o "$v2dat_dir/rules/local-ptr.txt" "https://raw.githubusercontent.com/sbwml/luci-app-mosdns/v5/luci-app-mosdns/root/etc/mosdns/rule/local-ptr.txt"
}

geodat_update
v2dat_dump
# update_local_ptr

# touch $v2dat_dir/rules/force-nocn.txt
# touch $v2dat_dir/rules/force-cn.txt
# force-cn 是强制本地解析域名，force-nocn 是强制非本地解析域名
