#!/bin/sh

dir="$1"
syscall="$2"
member="$3"

st_member="st_${member}"
path="${dir}/test_${syscall}_${member}"
if [ "${syscall}" != "lstat" ]; then
	opt=""
else
	opt=" -L"
fi
if [ "${member}" != "mode" ]; then
	stdout="\${${st_member}}"
else
	stdout="\$(\${tests_dir}/o2d/o2d \${st_mode})"
fi

echo -n "
dir=\$(dirname \$0)

. \"\${tests_dir}/${syscall}.rc\"

args=\"\${file} ${st_member}\"
eval \$(stat -s${opt} \"\${file}\")
expected_stdout=\"${stdout}\"

# vim: filetype=sh
" > ${path}
