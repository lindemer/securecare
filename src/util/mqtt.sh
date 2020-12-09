#!/bin/bash

alarm="obj/lidar/1/alarm"
noise="obj/lidar/1/noise"
host="192.168.1.1"

while read -r line
do
  n="$(cut -d',' -f1 <<< "$line")"
  msg="$(printf "\'{\"value\":%d,\"timestamp\":%d}\'" $n $(date +%s))"
  mosquitto_pub -h $host -t $noise -m $msg
 
  a="$(cut -d',' -f2 <<< "$line")"
  msg="$(printf "\'{\"value\":%d,\"timestamp\":%d}\'" $a $(date +%s))"
  mosquitto_pub -h $host -t $alarm -m $msg
done
