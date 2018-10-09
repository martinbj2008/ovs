mkdir -p /root/ovs-last
if [ -f /usr/sbin/ovs-vswitchd ] && [ -f /usr/sbin/ovsdb-server ];then
/usr/bin/cp -f /usr/sbin/ovs-vswitchd /usr/sbin/ovsdb-server /root/ovs-last
fi
