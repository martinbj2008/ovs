============
ovs-dpdk deploy
============

apply ovs-ctl patch to ovs-dpdk source

- git apply --stat usertools/0001-ADD-ovs-dpdk-configs-via-ovs-ctl.patch
- git apply --check usertools/0001-ADD-ovs-dpdk-configs-via-ovs-ctl.patch
- git am -s usertools/0001-ADD-ovs-dpdk-configs-via-ovs-ctl.patch
- git diff

deploy ovs-dpdk

- step1_pre_check.sh : check basic environment
- rpm -ivh ovs-dpdk-1.0-dpdk.x86_64.rpm : install ovs-dpdk package mannul or via step2_ovs_start.sh
- step2_ovs_start.sh : start ovsdb-server/ovs-vswitchd
- step3_post_check.sh : check weather ovsdb-server/ovs-vswitchd start success

to further

- step4_ovs_stop.sh : stop ovsdb-server/ovs-vswitchd
- step5_ovs_restart.sh : restart ovsdb-server/ovs-vswitchd

ovs-ctl
---------------------

Add set_dpdk_configs () to set option relate to dpdk, such as:

- ovs-vsctl set Open_vSwitch . other_config:dpdk-init=$DPDK_INIT
- ovs-vsctl set Open_vSwitch . other_config:dpdk-lcore-mask=$DPDK_LCORE
- ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=$DPDK_PMD_CPU
- ovs-vsctl set Open_vSwitch . other_config:dpdk-socket-mem=$DPDK_SOCK_MEM

step1_pre_check.sh
------------

- operate system version
- qemu-kvm version
- ovs-dpdk rpm
- hugepage info
- iommu/intel_iommu option
- vfio bond port

step2_ovs_start.sh
--------------------------------------

- start ovsdb-server/ovs-vswitchd process

step3_post_check.sh
-------

Check ovsdb-server/ovs-vswitchd process status

- ovsdb-server process status
- ovs-vswitchd process status

step4_ovs_stop.sh
--------------------------------------

- stop ovsdb-server/ovs-vswitchd process

step5_ovs_restart.sh
-------

- restart ovsdb-server/ovs-vswitchd process
