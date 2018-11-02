if [ -f /tmp/ovs-dpdk.conf ];then
    curr_mode=`grep "OVS_MODE" /tmp/ovs-dpdk.conf|gawk -F '=' '{print $2}'|sed 's/\"//g'`
    sed -ie "s/OVS_MODE=\"active\"/OVS_MODE=\"$curr_mode\"/g" /etc/openvswitch/ovs-dpdk.conf
    #rm -f /tmp/ovs-dpdk.conf
fi

cd /tmp/python/
python setup.py install 2>/dev/null  > /dev/null

systemctl daemon-reload
systemctl enable openvswitch

supervisorctl update > /dev/null

sed -ie "/recover/d" /etc/rc.local && echo "/usr/bin/recover" >> /etc/rc.local
