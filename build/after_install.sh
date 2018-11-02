if [ -f /tmp/ovs-dpdk.conf ];then
    curr_mode=`grep "OVS_MODE" /tmp/ovs-dpdk.conf|gawk -F '=' '{print $2}'|sed 's/\"//g'`
    sed -ie "s/OVS_MODE=\"active\"/OVS_MODE=\"$curr_mode\"/g" /etc/openvswitch/ovs-dpdk.conf
    #rm -f /tmp/ovs-dpdk.conf
fi

cd /tmp/python/
python setup.py install
