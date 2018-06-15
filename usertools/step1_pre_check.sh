#!/bin/bash

# Pre Check ovs-dpdk env.

logdir='/usr/local/var/log/openvswitch'
rundir='/usr/local/var/run/openvswitch'
sysconfdir='/etc'
etcdir='$sysconfdir/openvswitch'     
datadir='/usr/local/share/openvswitch'
dbdir='/usr/local/etc/openvswitch'
bindir='/usr/bin'
sbindir='/usr/sbin'

mountdir='/dev/hugepages'

DB_FILE=$dbdir/conf.db
DB_SOCK=$rundir/db.sock
DB_SCHEMA=$datadir/vswitch.ovsschema

KERNEL_VERSION="3.10.0-514.16.1.chishui01.x86_64"
QEMU_VERSION="qemu-kvm-ev-2.9.0-16.el7_4.14.2.x86_64"

SRIOV_NUM=2
NR_HUGEPAGES=2048

osCheck()
{
    echo -e "\e[1;32m[ovs-dpdk] Checking system version \e[0m" 	
    echo ""	

    sysOS=`uname -r`

    if [ $sysOS == $KERNEL_VERSION ]; then
        echo -e "\e[1;32m[ovs-dpdk] System OS version is expected \e[0m" 	
        echo ""	
    else
        echo -e "\e[1;31m[ovs-dpdk] $HOST System OS version supposed be $KERNEL_VERSION \e[0m"
        echo ""	
        exit -1
    fi
}

iommuCheck()
{
    dmesg | grep -e DMAR -e IOMMU > /dev/null
    if [ $? -ne 0 ] ; then
        echo -e "\e[1;32m[ovs-dpdk] VT-d supposed enabled in the BIOS \e[0m"
        echo ""	
        exit -1
    fi

    iommu=`cat /proc/cmdline | grep iommu=pt`
    intel_iommu=`cat /proc/cmdline | grep intel_iommu=on`
    if [[ $iommu && $intel_iommu ]];then
        echo -e "\e[1;32m[ovs-dpdk] VT-d is enabled in the kernel \e[0m"
        echo ""	
    else
        echo -e "\e[1;31m[ovs-dpdk] VT-d not enabled in the kernel \e[0m"
        echo ""	
        exit -1
    fi
}

numaCheck()
{
    isNuma=`lscpu |grep "NUMA node(s):" |awk '{print $NF}'`
    if [ $isNuma -eq 1 ]; then
        echo -e "\e[1;31m[ovs-dpdk] NUMA is not enabled , to operate \e[0m"
        echo ""	
    else
        echo -e "\e[1;32m[ovs-dpdk] NUMA is enabled in the kernel \e[0m"
        echo ""	
    fi
    
}

threadCheck()
{
    cores=`lscpu |grep "Thread(s) per core" | awk '{print $NF}'`
    if [ $cores -eq 2 ]; then
        echo -e "\e[1;32m[ovs-dpdk] Hyper-Threading is enabled in the kernel \e[0m"
        echo ""	
    else
        echo -e "\e[1;31m[ovs-dpdk] Hyper-Threading is not enabled in the kernel \e[0m"
        echo ""	
        exit -1
    fi
}

qemuCheck()
{
    rpm -qa | grep $QEMU_VERSION > /dev/null
    if [ $? -ne 0 ] ; then
        echo -e "\e[1;31m[ovs-dpdk] Qemu Version supposed be $QEMU_VERSION \e[0m"
        echo ""	
        exit -1
    fi
}

hugepageCheck()
{
    grep -s "$mountdir" /proc/mounts > /dev/null
    if [ $? -ne 0 ] ; then
        mount -t hugetlbfs none $mountdir
    fi

    echo $NR_HUGEPAGES > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
    echo $NR_HUGEPAGES > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

    pagesize=`awk '/Hugepagesize/ {print $2}' /proc/meminfo`
    pagetotal=`awk '/HugePages_Total/ {print $2} ' /proc/meminfo`
    if [ $pagesize -a $pagetotal ] ; then
        echo -e "\e[1;32m[ovs-dpdk] Hugepage size : $pagesize Hugepage Total : $pagetotal \e[0m"
        echo ""	
    else
        echo -e "\e[1;31m[ovs-dpdk] Mount Hugepage failed \e[0m"
        echo ""	
        exit -1
    fi
}

toolsCheck()
{
    if [ ! -f "$sbindir/dpdk-devbind" ]; then
        yum install dpdk-tools.x86_64 -y > /dev/null
    fi

    if [ ! -f "$sbindir/dpdk-devbind" ]; then
        echo -e "\e[1;31m[ovs-dpdk] dpdk-devbind tools uninstalled \e[0m"
        echo ""	
        exit -1
    else
        echo -e "\e[1;32m[ovs-dpdk] dpdk-devbind tools installed \e[0m"
        echo ""	
    fi
}

sriovCheck()
{
    device1=`cat /proc/net/bonding/bond4 | grep "Slave Interface:" | gawk '{print $3}' | sed -n '1p'`
    device2=`cat /proc/net/bonding/bond4 | grep "Slave Interface:" | gawk '{print $3}' | sed -n '2p'`
    if [[ $device1 && $device2 ]];then
        dev1_num=`cat /sys/class/net/$device1/device/sriov_numvfs`
        dev2_num=`cat /sys/class/net/$device2/device/sriov_numvfs`
        lspci | grep 'Virtual Function' > /dev/null
        if [ $? -ne 0 ] ; then
            echo $SRIOV_NUM > /sys/class/net/$device1/device/sriov_numvfs
            echo $SRIOV_NUM > /sys/class/net/$device2/device/sriov_numvfs
            ip link set $device1 vf 0 spoofchk off
            ip link set $device1 vf 1 spoofchk off
            ip link set $device2 vf 0 spoofchk off
            ip link set $device2 vf 1 spoofchk off
        fi
    else
        echo -e "\e[1;31m[ovs-dpdk] NIC num is not expected \e[0m"
        echo ""	
        exit -1
    fi
}

vfioCheck()
{
    $sbindir/dpdk-devbind --status | grep "drv=vfio-pci" > /dev/null
    if [ $? -eq 0 ] ; then
        echo -e "\e[1;32m[ovs-dpdk] VFIO module bond VF port success \e[0m"
        return 1
    fi

    modprobe vfio-pci

    /sbin/lsmod | grep -s vfio_pci > /dev/null
    if [ $? -ne 0 ] ; then
        echo -e "\e[1;31m[ovs-dpdk] VFIO module modprobe failed \e[0m"
        echo ""	
        exit -1
    else
        echo -e "\e[1;32m[ovs-dpdk] VFIO module modprobe success \e[0m"
        echo ""	
    fi

    /usr/bin/chmod a+x /dev/vfio
    /usr/bin/chmod 0666 /dev/vfio/*

    vf_pci1=`lspci |grep X710|grep  Virtual | gawk '{print $1}' | sed -n '1p'`
    vf_pci2=`lspci |grep X710|grep  Virtual | gawk '{print $1}' | sed -n '3p'`
    if [[ $vf_pci1 && $vf_pci2 ]];then
        $sbindir/dpdk-devbind --bind=vfio-pci $vf_pci1
        $sbindir/dpdk-devbind --bind=vfio-pci $vf_pci2
    else
        echo -e "\e[1;31m[ovs-dpdk] VF Port num is not expected \e[0m"
        echo ""	
        exit -1
    fi

    $sbindir/dpdk-devbind --status | grep "drv=vfio-pci" > /dev/null
    if [ $? -ne 0 ] ; then
        echo -e "\e[1;31m[ovs-dpdk] VFIO module bond VF port failed \e[0m"
        echo ""	
        exit -1
    else
        echo -e "\e[1;32m[ovs-dpdk] VFIO module bond VF port success \e[0m"
        echo ""	
    fi
}


echo
echo '===== OVS-DPDK Pre Check ====='
echo

osCheck
iommuCheck
numaCheck
threadCheck
qemuCheck
hugepageCheck
toolsCheck
sriovCheck
vfioCheck

echo
echo '===== END ====='
