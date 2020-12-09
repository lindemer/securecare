IFS=',' # internal field separator

alarm="obj/lidar/1/alarm"
noise="obj/lidar/1/noise"

while read line
do
  read -a strarr <<< "$line"
  mosquitto_pub -t $noise -m {\"value\":$strarr[0],\"timestamp\":$(date +%s)}
  mosquitto_pub -t $alarm -m {\"value\":$strarr[1],\"timestamp\":$(date +%s)}
done < "${1:-/dev/stdin}"
