#to set interface in monitor mode
INTERFACE=$1

ip link set $INTERFACE down
iwconfig $INTERFACE mode monitor
ip link set $INTERFACE up
