#!/bin/sh

dir="$1"
syscall="$2"

path="${dir}/${syscall}.rc"

echo -n "
cmd=\"${syscall}/${syscall}\"
file=\"\${tests_dir}/song\"

# vim: filetype=sh
" > ${path}

