#!/bin/bash

# Check ovsdb-server & ovs-vswitchd process status

logdir='/usr/local/var/log/openvswitch'
rundir="/usr/local/var/run/openvswitch"
sysconfdir='/etc'
etcdir='$sysconfdir/openvswitch'     
datadir='/usr/local/share/openvswitch'
dbdir='/usr/local/etc/openvswitch'
bindir='/usr/bin'
sbindir='/usr/sbin'

DB_FILE=$dbdir/conf.db
DB_SOCK=$rundir/db.sock
DB_SCHEMA=$datadir/vswitch.ovsschema

KERNEL_VERSION="3.10.0-514.16.1.chishui01.x86_64"

osCheck()
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

arp_is_learning () 
{
    pidfile=$rundir/$1.pid
    if test -e "$pidfile"; then
        if pid=`cat "$pidfile"`; then
            ctlfile=$rundir/$1.$pid.ctl
            test -e "$ctlfile" && Gw=`ip route show default | awk '/default/ {print $3}'` && ovs-appctl -t ctlfile tnl/route/show | grep $Gw
        fi     
    fi
} >/dev/null 2>&1

arpCheck () 
{
    if arp_is_learning ovs-vswitchd; then
        echo -e "\e[1;31m[ovs-dpdk] Gw arp has been learned by ovs-vswitchd \e[0m"
        echo ""	
    else
        echo -e "\e[1;31m[ovs-dpdk] Gw arp has not been learned by ovs-vswitchd \e[0m"
        echo ""	
        exit
    fi
}

pid_exists () {
    test -d /proc/"$1"
}

pid_comm_check () {
    [ "$1" = "`cat /proc/$2/comm`" ]
}

daemon_status () {
    pidfile=$rundir/$1.pid
    if test -e "$pidfile"; then
        if pid=`cat "$pidfile"`; then
            if pid_exists "$pid"; then
                echo -e "\e[1;32m[ovs-dpdk] $1 is runnning with pid $pid \e[0m" 	
                echo ""	
                return 0
            else
                echo -e "\e[1;32m[ovs-dpdk] Pidfile for $1 ($pidfile) is stale \e[0m" 	
                echo ""	
            fi
        else
            echo -e "\e[1;32m[ovs-dpdk] Pidfile for $1 ($pidfile) exists but cannot be read \e[0m" 	
            echo ""	
        fi
    else
        echo -e "\e[1;32m[ovs-dpdk] $1 is not runnning \e[0m" 	
        echo ""	
    fi
    return 1
}

daemon_is_running () {
    pidfile=$rundir/$1.pid
    test -e "$pidfile" && pid=`cat "$pidfile"` && pid_exists "$pid" && pid_comm_check $1 $pid
} >/dev/null 2>&1

check_ovsdb_server () {
    if daemon_is_running ovsdb-server; then
        daemon_status ovsdb-server
    else
        daemon_status ovsdb-server
        exit -1
    fi
}

check_ovs_vswitchd () {
    if daemon_is_running ovs-vswitchd; then
        daemon_status ovs-vswitchd
    else
        daemon_status ovs-vswitchd
        exit -1
    fi
}

echo
echo '===== OVS-DPDK Post Check ====='
echo

osCheck
check_ovsdb_server
check_ovs_vswitchd
arpCheck

echo
echo '===== END ====='
