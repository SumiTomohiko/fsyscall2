
fsyscall
********

NOTICE: fsyscall is under development. Some features described in this
documentation are not still implemented.

Overview
========

fsyscall is a system to transfer system call requests from applications on
FreeBSD to another process through file descriptors. If you give a socket for
the file descriptors, fsyscall can request system calls to another machine
through network.

.. image:: overview.png

The follwing three figures show you one example of fsyscall's work.

1. When an application calls open(2), fsyscall sends it to another machine.
2. The requested machine does open(2) actually.
3. The machine sends a returned value of open(2) or errno. fsyscall gives it to
   the application.

.. image:: example1.png
.. image:: example2.png
.. image:: example3.png

fsyscall does not require any modifications on applications.

Expected merits of fsyscall are:

* using applications on FreeBSD from a non-FreeBSD machine such as Android.
* using a remote powerful machine as a local machine.
* maintaining remote machines with applications in a local machine.

There is a demerit:

* throughput of network I/O becomes that of file I/O.

NOTICE: fsyscall does not have any functions to connect a local machine to a
remote machine. It is a role of other applications. nexec_ is one example. nexec
connects a local slave machine to a remote master machine (the following section
explains "master" and "slave").

.. _nexec: http://neko-daisuki.ddo.jp/~SumiTomohiko/nexec/index.html

Master and slave
================

In fsyscall, a machine requesting system calls is called as a "master". A
"slave" is defined as a machine accepting system calls.

.. image:: master_and_slave.png

A local machine as a master
---------------------------

.. image:: a_local_machine_as_a_master.png

A local machine as a slave
--------------------------

.. image:: a_local_machine_as_a_slave.png

Structure
=========

Restrictions
============

Download
========

How to compile/install
======================

How to use
==========

How to start a master
---------------------

How to start a slave
--------------------

Author
======

.. vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
