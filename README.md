---
---
# RHEL Troubleshooting Guide

GitHub repo: [https://github.com/myllynen/rhel-troubleshooting-guide](https://github.com/myllynen/rhel-troubleshooting-guide)  
Themed page: [https://myllynen.github.io/rhel-troubleshooting-guide](https://myllynen.github.io/rhel-troubleshooting-guide)

## Introduction

This page provides a compact guide to
[Red Hat Enterprise Linux (RHEL)](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux)
troubleshooting on bare metal and virtualization platforms like
[OpenShift Virtualization](https://www.redhat.com/en/technologies/cloud-computing/openshift/virtualization)
and
[OpenStack](https://www.redhat.com/en/technologies/linux-platforms/openstack-platform).

For further help with [Red Hat](https://www.redhat.com/en)
[products](https://www.redhat.com/en/technologies/all-products) be sure
to contact
[Red Hat Support](https://www.redhat.com/en/services/support) using the
official channels, for details see
[Red Hat Customer Portal](https://access.redhat.com/).
[Red Hat Support Scope of Coverage](https://access.redhat.com/support/offerings/production/soc)
describes what Red Hat will and will not support.

For performance tips see
[https://github.com/myllynen/rhel-performance-guide](https://github.com/myllynen/rhel-performance-guide).

## Checking for Known Issues

Before spending hours or even days trying to troubleshoot an issue, it
is a good idea to check for known issues that might affect the
situation. In fact, best would be to check for these known issues
proactively to avoid them having any effect in the first place.

[Red Hat Insights](https://www.redhat.com/en/technologies/management/insights)
is included as part of
[RHEL subscription](https://www.redhat.com/en/resources/red-hat-enterprise-linux-subscription-guide)
and can automatically identify a large number of known issues and
solutions. Insights can also be
[integrated](https://www.redhat.com/en/blog/integrating-monitoring-system-red-hat-insights)
with a monitoring solution.

Tools and services which can help you to find known issues include:

* [Red Hat Customer Portal](https://access.redhat.com/)
* [Red Hat Knowledge Base](https://access.redhat.com/knowledgebase)
* [Red Hat Insights](https://access.redhat.com/products/red-hat-insights/)
* [Red Hat Issue Tracker](https://issues.redhat.com/)
* [Red Hat Troubleshooting Labs](https://access.redhat.com/labs/?type=troubleshoot)

## Basic System Level Sanity Checking

Initially it is a good idea to quickly verify that the system (virtual)
hardware setup is as expected: the number of processors, the amount of
memory, the disk and file system layout, and the network devices. Use
the following commands to see how the system basics looks like:

```
lscpu
lsmem
lsblk
ip a
```

Check the recent lines of
[dmesg(1)](https://man7.org/linux/man-pages/man1/dmesg.1.html) output to
make sure there have not been any (virtual) hardware, driver, or kernel
internal issues (like filesystem or storage errors) reported. In case of
hardware issues, please investigate the (virtual) hardware platform side
in more detail. Kernel filesystem issues are often symptoms of lower
level issues like storage connectivity and consistency. See the next
section for more hints on other kernel level messages.

```
dmesg -T
```

Check the system status in general with
[top(1)](https://man7.org/linux/man-pages/man1/top.1.html) to make sure
no unexpected processes are running or eating all CPU cycles and that
there is no notable IO wait. High IO wait might indicate storage issues
which cause the system to slowdown in general. Also note the system
uptime so that there have not been any unexpected reboots recently (due
to manual intervention or a kernel crash).

```
top
```

Use [execsnoop(8)](https://www.mankier.com/8/execsnoop) (from the
_bcc-tools_ package) to verify that no large amount of short-lived
processes are being run constantly. Such processes would not often be
visible in [top(1)](https://man7.org/linux/man-pages/man1/top.1.html)
output.

```
/usr/share/bcc/tools/execsnoop
```

Check the recent messages in system logs to see if anything unusual has
been reported recently. There might also be information about crashed
processes which would indicate application level issues.

```
journalctl -l -b | less
less /var/log/messages
less /var/log/secure
```

When using SELinux in Enforcing mode (as it
[should](https://stopdisablingselinux.com/) be) it is worth checking for
possible SELinux denials with interpretations:

```
ausearch -m AVC -i 
```

Additional SELinux related information can be found with the commands
below, see the
[ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html)
manual page for more information:

```
grep denied /var/log/audit/audit.log
ausearch -i --input /var/log/audit/audit.log
ausearch -ts 12/24/2024 12:00:00
```

Consider checking current and recent system performance metrics with
[Performance Co-Pilot](https://pcp.io/) and its
[pmrep(1)](https://man7.org/linux/man-pages/man1/pmrep.1.html) utility
or with
[sysstat](https://github.com/sysstat/sysstat)/[sar(1)](https://man7.org/linux/man-pages/man1/sar.1.html).
For more details on performance related issues see
[https://github.com/myllynen/rhel-performance-guide](https://github.com/myllynen/rhel-performance-guide).

## Basic Application Level Sanity Checking

As mentioned above, system logs might contain traces of application
crashes which should be investigated further. If a crash is in a RHEL
component, please contact
[Red Hat Support](https://www.redhat.com/en/services/support) but please
keep in mind that root cause analysis (RCA) and fixing the issue might
be impossible without the corresponding application core dump. In case
core dumps are disabled, please refer to
[https://access.redhat.com/solutions/56021](https://access.redhat.com/solutions/56021)
and
[https://access.redhat.com/solutions/649193](https://access.redhat.com/solutions/649193)
on how to enable core dumps to then reproduce the issue with core dumps
enabled. An easy way to test whether core dumps are enabled is to send
the SEGV signal to a running (non-critical!) process, for example `kill
-SEGV $(pidof chronyd)`, this ought to trigger core dump creation when
core dumps have been enabled.

If an application has not crashed but is misbehaving or unresponsive,
check all available logs for errors, warnings, or unusual activity.
Ensure that no firewalls or recent network configuration changes are
preventing access. Identify the affected application carefully, as
issues in a lower-level application may impact a higher-level one.

For example, in case an application is heavily relying on LDAP, if the
LDAP server is providing responses to queries from the command line as
expected and the logs for the LDAP server do not contain anything unsual
then the higher level application using LDAP is probably having internal
issues and the LDAP server itself is working properly. On the other hand
if the LDAP server does not reply even to basic queries from the command
line or its logs contain errors and warnings then those issues should be
sorted out first before investigating the application relying on LDAP
further.

### General Application Troubleshooting Tips

First investigate if there has been any recent changes or updates to the
installed software:

```
rpm -qa --last | less
tail /var/log/dnf.log
```

Then investigate the application configuration and make sure what is
currently configured in the configuration files is actually in use by
the running application process.

To see all the files changed since installation (from RPMs) use:

```
rpm -Va
```

This will check all files from all packages and can take a while. The
results will highlight what kind of customizations have been made to the
system. See
[rpm(8)](https://man7.org/linux/man-pages/man8/rpm.8.html) for
explanation of the output of the command. Note that there might be some
expected and packaging related changes reported so there will be some
output from this command even on a pristine system.

To check changes in certain packages use:

```
rpm -V PKG1 PKG2
```

If the application is logging at least parts of its activities to the
system log, it is a good idea to add markers to the system log to
highlight when a test run was starting and ending, for example:

```
logger TEST-START
/path/to/app --test
logger TEST-END
```

If it is unclear which files an application or a component is changing
during its execution it is possible to find out the changed files with:

```
touch /tmp/ts
/path/to/app --test
find / -newer /tmp/ts -print 2> /dev/null | grep -Ev '^/(proc|sys)' | sort
```

Sometimes it is also helpful to see what (configuration) files the
application is actually accessing (use `-p` to attach to a running
process):

```
strace -e open,openat,open_by_handle_at -ff /path/to/app --test
```

[strace(1)](https://man7.org/linux/man-pages/man1/strace.1.html) can
also be used to check some basic networking behavior of an application,
for example whether it is communicating with a certain host:

```
strace -ff /path/to/app --test 2>&1 | grep 192.168.122.100
```

While the above can be used as a quick test and might give some hints,
for real network related troubleshooting it is of course better to use
[tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html).

## Checking Recent Changes in System

Often a recently made change may be related to the issue at hand. In
case a centralized configuratiom management system (such as
[Ansible Automation Platform](https://access.redhat.com/products/red-hat-ansible-automation-platform/))
is in use, recent updates to its content should be reviewed. The details
of configuration management systems are out of scope for this guide but
it should be kept in mind that local configuration changes may be
periodically overwritten by such centralized tools.

Sometimes it is useful to see if someone has recently logged into to a
system and review possible changes by them. To see users recently logged
into the system and the commands they have run:

```
last -F
less ~USERNAME/.bash_history
journalctl -r _UID=UID
```

Note that a rogue user can easily avoid recording their command history
in the shell history file and that the local privacy regulations should
be respected when investigating possible actions by other users. On the
other hand, in some cases session recording might be mandatory for
compliance and regulatory reasons.

Recent local changes made with
[sudo(8)](https://man7.org/linux/man-pages/man8/sudo.8.html) can be
investigated with:

```
journalctl -r _COMM=sudo | less
```

To compare two (perhaps supposedly identical) systems there are a few
ways to see differences between them.

To compare installed packages and their versions across two systems run
the following command on both:

```
rpm -qa | sort > $(hostname)-rpms.txt
```

Then compare the installed packages by running:

```
diff -u HOST1-rpms.txt HOST2-rpms.txt
```

[diff(1)](https://man7.org/linux/man-pages/man1/diff.1.html) could be
used for checking other things like kernel parameters or the contents of
the /etc directories as well. Use `sysctl -a | sort` to dump current
kernel parameters and `diff -purN DIR1 DIR2` the compare the contents of
two directories.

When dealing with a large number of systems it is more typical to use
automated baseline and health check playbooks to ensure the expected
state of the systems.

Please note that 3rd party
[kernel modules](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_monitoring_and_updating_the_kernel/managing-kernel-modules_managing-monitoring-and-updating-the-kernel)
may cause unexpected issues even outside of their supposed feature
domain (for instance, a 3rd party VPN kernel module once broke the
kernel file system monitoring events functionality which in turn broke
some non-network applications). See also
[https://access.redhat.com/solutions/4246821](https://access.redhat.com/solutions/4246821)
and
[https://access.redhat.com/solutions/40594](https://access.redhat.com/solutions/40594)
for more information about kernel modules.

### Checking Changes in Package Contents

Sometimes it is helpful to check what changes have been introduced in
newer (Red Hat) RPM packages.

Note that the basic version numbers of RHEL packages do not fully
indicate what fixes are included in packages as Red Hat backports
notable security fixes (and sometimes features as well) in a
backward-compatible way to RHEL packages. See
[https://www.redhat.com/en/blog/what-backporting-and-how-does-it-apply-rhel-and-other-red-hat-products](https://www.redhat.com/en/blog/what-backporting-and-how-does-it-apply-rhel-and-other-red-hat-products)
and
[https://www.redhat.com/en/blog/what-latest-kernel-release-my-version-red-hat-enterprise-linux](https://www.redhat.com/en/blog/what-latest-kernel-release-my-version-red-hat-enterprise-linux)
for details.

One option to consider is using the dnf security plugin for security
related fixes, see
[https://access.redhat.com/solutions/10021](https://access.redhat.com/solutions/10021).
Another quick way to see fixed issues and CVEs is to check the RPM
changelog:

```
rpm -q --changelog PKG | less
```

This often already gives enough information but more detailed list of
changes can be checked with the
[rpmdiff(1)](https://www.mankier.com/1/rpmdiff) utility (from the
_rpmlint_ package):

```
rpmdiff package-old.rpm package-new.rpm
```

Even more detailed information can be checked by comparing the files
included in the old and the new package, this useful if the changes are
mostly in configurations and scripts contained in the packages, not in
the binaries:

```
mkdir old new
cd old
rpm2cpio ../old-package.rpm | cpio -imdv
cd ../new
rpm2cpio ../new-package.rpm | cpio -imdv
cd ..
diff -purN old new | less
```

Occasionally pre/post scripts of (3rd party) packages cause surprises,
they can be inspected with:

```
rpm -q --scripts PKG
```

## Understanding System Memory Usage

Sometimes it might seem - or there is even an alarm generated by certain
second-grade monitoring tools - that a RHEL system is soon running out
of memory. For example, on RHEL 9
[free(1)](https://man7.org/linux/man-pages/man1/free.1.html) might show
something like:

```
$ free -m
              total        used        free      shared  buff/cache   available
Mem:          15921        4310        8582         629        3028       10650
Swap:          8193           0        8193
```

On the surface it might look like the system has only half of its memory
free for applications (8582M out of 15921M). This is, of course, not the
case here. As the rightmost column shows, the available memory when
excluding buffers/cache is 10650M. This memory use for buffers/cache is
perfectly normal and a good thing. When the kernel uses otherwise unused
memory (that is, applications are not using that much memory currently)
for buffering block device data and caching filesystem contents, it
means that there will be less physical disk operations needed if and
when applications access the same devices and files again later. If at
some point applications request more memory than is currently free due
to buffering and caching the kernel will automatically and transparently
free up some previously used buffer/cache memory for applications. Thus
there should be no efforts made by administrators to avoid kernel
buffering and caching altogether.

For some related details, see
[https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=34e431b0ae398fc54ea69ff85ec700722c9da773](https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=34e431b0ae398fc54ea69ff85ec700722c9da773).

While buffering and caching is a good thing constant paging and swapping
is not and extreme swapping can render the system almost completely
unresponsive. The most important swapping metric is swapping activity,
that is, how much pages are being swapped in and out, not the plain
amount of swap currently in use. There might be a portion of swap in use
at any given time but in case there is no constant swapping activity
then this swap usage is a merely a sign that there has been a memory
pressure situation in the past and the kernel has paged out some idle
pages or processes to make room for actively running applications, or
perhaps for buffering and caching. Since all modern operating systems
use demand paging the swapped out pages are not proactively swapped back
into the main memory until there is a real need for them so swap may
remain long used after a memory pressure situation.

Use `pmrep :sar-W` (with PCP) or `sar -W 1` (with sysstat) to monitor
swapping activity on a system. See
[https://chrisdown.name/2018/01/02/in-defence-of-swap.html](https://chrisdown.name/2018/01/02/in-defence-of-swap.html)
for discussion on swap.

## Understanding Kernel Issues and Internal Messages

A kernel bug might lead to a kernel hang or crash (panic).

A kernel crash causes (when
[kdump](https://access.redhat.com/solutions/6038)
is enabled) the system to save the kernel memory and state dump (vmcore)
in _/var/crash_ (by default) and rebooting the system. Kernel crashes
leave no traces to system logs but system logs which contain no messages
about the system being shutdown and then suddenly show kernel bootup
messages might be a hint of a kernel crash. The kernel internal memory
and state dump will be crucial when investigating kernel issues.

Kernel hangs are harder to detect, some parts of the system might be
operating almost normally while some subsystems are stuck (e.g.,
networking works but filesystems not, or vice versa). In such cases it
is unlikely that system internal monitoring can reliably raise an alarm
or force the kernel to crash in order to create a vmcore. In case of a
virtual machine (VM), a VM core dump collected from the hypervisor side
is needed in these cases. For a generic vmcore capturing information on
KVM (including OpenShift Virtualization and OpenStack), see
[https://access.redhat.com/solutions/39604](https://access.redhat.com/solutions/39604).

Sometimes the system log (and the output of `dmesg`) might contain
information about soft lockups or hung tasks. The system may or may not
be operating normally after such occurrences, depending on the
situation, see below for more details on these.

In some very rare corner cases a kernel driver might crash without
crashing the entire kernel and thus the functionality provided by the
driver (for instance, networking) is defunct after the fact. System logs
often contain traces about such incidents. However, a driver crash
almost always leads also to a complete kernel crash.

### Kernel Crash

Kernel crashes are always something that must be investigated on a
case-by-case basis. It is always recommended to get Red Hat Support
involved for these investigations (unless it is possible to verify that
a crash is due to a known issue verified earlier already).

A complete kernel core dump (vmcore) is required for kernel crash RCA,
without a vmcore it is impossible to determine the root cause.

### Kernel Hang

Kernel hangs are trickier to identify and deal with than outright kernel
crashes. First of all, it is important to acknowledge that if a host or
a guest VM is under extreme load and application responses from guests
are painfully slow this still does not mean at all that the kernel has
hung. A kernel hang manifests itself usually so that some tasks (e.g.,
accessing certain filesystems) literally never complete.

System internal monitoring may or may not detect a kernel hang. If a
service running on the system is affected by hang but monitoring is not,
then it might be detected. Of course, if monitoring itself is also
affected by hang then internal monitoring is of no help. Since it is
impossible to predict beforehand what kind of hangs might occur it is
best to employ external application and system monitoring solutions in
addition to on-system monitoring ones.

If a kernel hang is suspected and it seems not possible to trigger a
kernel crash inside a guest then a guest core dump captured from the
hypervisor side will be needed. For more information about this, please
see
[https://access.redhat.com/solutions/39604](https://access.redhat.com/solutions/39604).

### Soft Lockup Messages

Sometimes kernel emits messages to the system log about soft lockups:

```
kernel: BUG: soft lockup - CPU#1 stuck for 60s! [<process>:<pid>]
```

Despite the "BUG" in the message this most often does not indicate a
kernel bug. As the message says, the kernel sees the CPU being stuck.

These messages are typically seen under heavy hypervisor load and as
such are symptoms not a cause. The host CPU might be busy doing
something else (for example, running other vCPUs or swapping in/out
guest memory pages) and the guest vCPU is not getting the CPU cycles the
guest kernel expects thus the guest kernel assumes there has been a CPU
lockup. Perhaps a bit confusingly, these messages may coincide with high
guest CPU load. The explanation is that if there is no need for (v)CPU
cycles on the guest the hypervisor high load situation would go
undetected by the guest kernel.

After seeing these messages troubleshooting efforts should not start
with the assumption that a kernel bug has been hit, it will be more
helpful to investigate the hypervisor, network, and storage side first.
There are few generic Red Hat Knowledge Base articles about this, see
for instance
[https://access.redhat.com/articles/371803](https://access.redhat.com/articles/371803).

If everything else has really been rules out, Red Hat Support can help
to investigate the issue further. In such case a kernel crash dump
(vmcore) is a must-have. For instructions how to crash the kernel
automatically when experiencing a soft lockup, please see
[https://access.redhat.com/solutions/19541](https://access.redhat.com/solutions/19541).

Note that crashing the kernel will (obviously) lead to imminent system
reboot causing downtime of the node, thus it should be done only when
other options do not help. The vmcore must be captured during the time
of the issue, manually crashing the kernel later on or system logs after
a reboot will not provide enough information about the situation.

### Blocked Task Messages

Sometimes kernel emits messages to the system log about a task (process)
being blocked for more than 120 seconds:

```
kernel: INFO: task <process>:<pid> blocked for more than 120 seconds.
```

This is not an indication of anything crashing or usually not even a
kernel bug. This is merely indicating that a certain process was not
proceeding as expected at that time and as such can be considered as a
warning if everything still works later on as expected.

There can be several reasons for seeing these messages: storage issues,
the system or the hypervisor being under extreme load leading to
resource starvation, or there might be a kernel bug causing the issue.

When encountering these messages, it is a good idea to check
[https://access.redhat.com/solutions/31453](https://access.redhat.com/solutions/31453)
for more detailed description of hung task messages and also search
for Red Hat Knowledge Base for related known issues.

If the system does not recover from such a situation by itself or it
occurs frequently with no indications of related known issues, Red Hat
Support can help identifying the root cause. However, a complete vmcore
will be required, the accompanying stack traces do not necessarily
contain all the needed information for RCA. First collect a sosreport
(see below) and then produce vmcore by manually crashing the kernel when
these messages are being logged:

```
echo 1 > /proc/sys/kernel/sysrq
sync ; echo 3 > /proc/sys/vm/drop_caches ;
echo c > /proc/sysrq-trigger
```

## File System Issues

Sometimes deleting a large file does not free up space on the file system.
This is most likely caused by the file being still open by a process,
see
[https://access.redhat.com/solutions/2316](https://access.redhat.com/solutions/2316).
To list deleted but open files on a mount point do:

```
lsof /mount/path | grep deleted
```

In case a file system cannot be unmounted consider using
[fuser(1)](https://man7.org/linux/man-pages/man1/fuser.1.html) to kill
the processes preventing the operation.

## Collecting sosreports

When there is an issue which looks like at least potentially or
partially a RHEL issue (after verifying it cannot be a (virtual)
hardware issue or a recently emerged misconfiguration), it is crucial
that all the needed information is collected from all the affected nodes
and very much preferably while the issue is still ongoing. Without
properly collected logs RCA is most often impossible.

The following command collects a sosreport from a node without asking
any questions and also captures older logs which may be needed as well:

```
sos report --all-logs --batch
```

In case the command seems to never finish, you must run it manually with
the problematic plugins disabled. Run `sos report -v` to see detailed
progress and to determine the plugin that hangs. Then kill the currently
running sosreport command and use the above command with the addition of
`-v -n <hanging-plugin>` parameters to allow sosreport to complete. In
case another plugin hangs as well, repeat the procedure and use a
comma-separated list to disable all the problematic plugins.

See
[https://access.redhat.com/solutions/3592](https://access.redhat.com/solutions/3592)
for more details on sosreports.

### Collecting Detailed Process Level Information

For many of issues sosreports provide a sufficient starting point and is
sometimes everything that is needed for troubleshooting by a support
team. However, in some cases detailed process level information is
needed, most typically this means a process core dump and/or process
stack (pstack) information and/or a strace capture from a running/stuck
process.

In case a stuck process has already been identified and the
process/system needs to be restarted to get everything back online, it
might be a good idea to collect application core dump and process stack
information proactively.

Please note that application core dumps may contain sensitive data
structures and information subject to privacy regulations. Also note
that the [pstack(1)](https://www.mankier.com/1/pstack) and
[gcore(1)](https://man7.org/linux/man-pages/man1/gcore.1.html) utitilies
used for this are part of the _gdb_ (GNU Debugger) package which may or
may not be suitable for installation on production systems. The details
of these caveats and data sensitivity issues are outside of the scope
for this guide, on technical level the procedure to collect the
information is as described below.

Collect process stack information of a live/running/stuck process:

```
pstack PID > pstack-output.txt
```

Collect core dump of a live/running/stuck process:

```
gcore PID
```

Collect [strace(1)](https://man7.org/linux/man-pages/man1/strace.1.html)
for a while of a live but potentially stuck process:

```
strace -ff -s 1024 -p PID > strace-output.txt 2>&1
```

For any crashed process a core dump is available in case core dumps are
enabled (but they are is also subject to the same data sensitivity
considerations as mentioned earlier). See
[https://access.redhat.com/solutions/56021](https://access.redhat.com/solutions/56021)
on how to collect core dumps.

## Collecting Additional Data from a Hung VM

As stated above, for complete analysis of kernel issues a kernel core
dump (vmcore) is required, without a vmcore it is impossible to
determine the root cause of an issue.

However, in some cases getting vmcore is hard or near impossible so any
additional clues might be helpful. In these kinds of cases the
[netconsole](https://www.kernel.org/doc/Documentation/networking/netconsole.txt)
functionality of the kernel, which emits all kernel messages to another
system in the network, could help. This requires the system still to be
somewhat operational, from an already crashed system nothing can be read
even with netconsole.

On a working system which will listen messages from the system under
investigation install
[ncat](https://man7.org/linux/man-pages/man1/ncat.1.html) (from the
_nmap-ncat_ package) and run:

```
nc -u -l 6666 > nc.log
```

On the system under investigation enable verbose logging and load the
netconsole kernel module, the IP to use is the address of the listening
system. Test the setup by running a command generating logging a few
times:

```
dmesg -n 8
modprobe netconsole netconsole=@/,@192.168.122.101/
echo s > /proc/sysrq-trigger
echo s > /proc/sysrq-trigger
```

This is not a full substitute for a vmcore but may in some cases provide
some additional clues. Please refer to
[https://www.kernel.org/doc/Documentation/networking/netconsole.txt](https://www.kernel.org/doc/Documentation/networking/netconsole.txt)
for full netconsole information.

## Collecting Data for Networking Issues

Generic tips about debugging networking issues are available at
[https://access.redhat.com/articles/1311173](https://access.redhat.com/articles/1311173).

A general port connection test was in the past usually performed with
the [telnet(1)](https://www.mankier.com/1/telnet) command. But nowadays
telnet is usually not installed by default on most systems. To avoid
having to install telnet it is possible to use
[curl(1)](https://man7.org/linux/man-pages/man1/curl.1.html) instead,
that is almost always installed by default, also in containers. To
perform connection tests to a specific port do:

```
curl -v telnet://HOSTNAME:PORT
```

Errors like "Destination unreachable (Host unreachable)" could mean
either a firewall preventing access or that there are
[ARP](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) issues
on the network. Historically the ARP cache could be displayed with the
[arp(8)](https://man7.org/linux/man-pages/man8/arp.8.html) command but
nowadays it is prefered to use the
[ip(8)](https://man7.org/linux/man-pages/man8/ip.8.html) command:

```
ip neigh
```

If network switch and other such issues have been ruled out and it looks
like the issue might be RHEL related, try narrowing down the cause as
much as possible, for example by trying different protocols
(SSH/HTTP/HTTPS/etc), different file sizes (1kB/1MB/etc), different
source/destination addresses/ports, and so forth. See if co-locating VMs
on the same/different host makes a difference (if so, investigate the
network infrastructure level in more detail). Obviously, make sure that
firewalls at any level are not blocking or dropping traffic. Check
counters for dropped packets (use
[ip(8)](https://man7.org/linux/man-pages/man8/ip.8.html),
[ethtool(8)](https://man7.org/linux/man-pages/man8/ethtool.8.html),
[nft(8)](https://www.mankier.com/8/nft), and
[ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html)). Consider
disabling/enabling all guest NIC offloading settings and/or increasing
NIC ring buffer values as possible.

If in doubt whether an issue is happening on a guest or hypervisor
level, for complete analysis full packet captures from all levels of the
infrastructure below guests will be needed. See
[https://access.redhat.com/solutions/4272142](https://access.redhat.com/solutions/4272142)
for description how
[tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
captures packets.

## Additional Information

* [RHEL documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/)
* [Red Hat Knowledge Base](https://access.redhat.com/knowledgebase/)
* [Red Hat Customer Portal](https://access.redhat.com/)
* [Linux Admin Troubleshooting video](https://www.youtube.com/watch?v=KZ8oEh3dTfw)

## See Also

See also
[https://myllynen.github.io/rhel-performance-guide/](https://myllynen.github.io/rhel-performance-guide/).
