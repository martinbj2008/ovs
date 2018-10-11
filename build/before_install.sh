rm -f /tmp/ovs-dpdk.conf
if [ -f /etc/openvswitch/ovs-dpdk.conf ];then
    mv /etc/openvswitch/ovs-dpdk.conf /tmp/
fi

mkdir -p /root/ovs-last
if [ -f /usr/sbin/ovs-vswitchd ] && [ -f /usr/sbin/ovsdb-server ];then
/usr/bin/cp -f /usr/sbin/ovs-vswitchd /usr/sbin/ovsdb-server /root/ovs-last
fi
