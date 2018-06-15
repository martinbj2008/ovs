#!/bin/bash

# Check ovs-dpdk rpm and start ovsdb-server/ovs-vswitchd

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

PKG=$1
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

pkgCheck()
{
    echo -e "\e[1;32m[ovs-dpdk] Checking ovs-dpdk package \e[0m" 	
    echo ""	

    rpm -qa | grep $PKG &>/dev/null

    if [ $? -ne 0 ]; then
        echo -e "\e[1;32m[ovs-dpdk] $PKG is not installed yet, starting to install \e[0m" 	
        echo ""
        rpm -ivh $PKG 2>>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "\e[1;32m[ovs-dpdk] $PKG is installation failed \e[0m" 	
            echo ""
            exit -1
        else
            echo -e "\e[1;32m[ovs-dpdk] $PKG is already installed \e[0m" 	
            echo ""
        fi
    else
        echo -e "\e[1;32m[ovs-dpdk] $PKG is already installed \e[0m" 	
        echo ""
    fi
}

echo
echo '===== OVS-DPDK Start ====='
echo

osCheck
pkgCheck
$scriptdir/ovs-ctl start

echo
echo '===== END ====='
