#!/bin/bash

# Check ovsdb-server & ovs-vswitchd process status

logdir='/usr/local/var/log/openvswitch'
rundir="/usr/local/var/run/openvswitch"
sysconfdir='/etc'
etcdir='$sysconfdir/openvswitch'     
scriptdir='/usr/local/share/openvswitch/scripts/'
datadir='/usr/local/share/openvswitch'
dbdir='/usr/local/etc/openvswitch'
bindir='/usr/bin'
sbindir='/usr/sbin'

DB_FILE=$dbdir/conf.db
DB_SOCK=$rundir/db.sock
DB_SCHEMA=$datadir/vswitch.ovsschema

KERNEL_VERSION="3.10.0-514.16.1.chishui01.x86_64"

ovsCheck()
{
    echo -e "\e[1;32m[ovs-dpdk] Checking system version \e[0m" 	
    echo ""	

    sysOS=`uname -r`

    if [ $sysOS == $KERNEL_VERSION ]; then
        echo -e "\e[1;32m[ovs-dpdk] System OS version is Correct \e[0m" 	
        echo ""	
    else
        echo -e "\e[1;31m[ovs-dpdk] $HOST System OS version supposed be $KERNEL_VERSION \e[0m"
        echo ""	
        exit -1
    fi
}

echo
echo '===== OVS-DPDK ReStart ====='
echo

osCheck

$scriptdir/ovs-ctl restart

echo
echo '===== END ====='
