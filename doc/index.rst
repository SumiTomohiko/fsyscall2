
fsyscall
********

NOTICE: fsyscall is under development. Some features described in this
documentation are not still implemented.

Overview
========

fsyscall is a system to transfer system call requests for file I/O from
applications on FreeBSD to another process through file descriptors. Application
do not need to be modified at all.

In the most expected usage, a socket is used for the file descriptors.

.. image:: overview.png

Expected merits of fsyscall are:

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
