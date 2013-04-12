
fsyscall
********

NOTICE: fsyscall is under development. Some features described in this
documentation are not still implemented.

Overview
========

fsyscall is a system to transfer system call requests from applications on
FreeBSD to another process through file descriptors. In the most expected usage,
a socket is used as file descriptors. This means that a user can use a process
in a remote machine as that in a local machine.

.. image:: overview.png

Expected merits are:

* using applications on FreeBSD from a non-FreeBSD machine such as Android.
* using a remote powerful machine as a local machine.
* maintaining remote machines with applications in a local machine.

There is a demerit:

* throughput of network I/O becomes that of file I/O.

Master and slave
================

.. image:: overview_of_system_call_flow.png

Hub system
==========

fsyscall transfers system calls which handles files.
====================================================

.. vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
