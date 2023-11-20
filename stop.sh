array=$(cat run.sh)
read -ra line <<< $array
len=${#line[@]}
fusermount -u ${line[$[len-3]]}