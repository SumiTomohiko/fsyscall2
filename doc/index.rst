
fsyscall
********

.. attention:: fsyscall is under development. Some features described in this
    documentation are not still implemented.

.. contents:: Table of contents

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

.. attention:: fsyscall does not have any functions to connect a local machine
    to a remote machine. It is a role of other applications. nexec_ is one
    example. nexec connects a local slave machine to a remote master machine
    (the following section explains "master" and "slave").

.. _nexec: http://neko-daisuki.ddo.jp/~SumiTomohiko/nexec/index.html

Master and slave
================

In fsyscall, a machine requesting system calls is called as a "master". A
"slave" is defined as a machine accepting system calls.

.. image:: master_and_slave.png

You can use your machine as both of a master and a slave. It depends on an
application which you use.

A local machine as a master
---------------------------

If you use your machine as a master, you can control a slave with applications
in your machine.

.. image:: a_local_machine_as_a_master.png

A local machine as a slave
--------------------------

When your machine is a slave, you can use a master FreeBSD machine as a local
machine. You can use CPU/memory/applications in the master. These applications
can read/write files in your slave machine.

nexec_ is an application for this case. If you use nexec_, your machine becomes
a slave. The client of nexec_ connects to a server which works as a master.

.. image:: a_local_machine_as_a_slave.png

If your machine is Android and someone implements slave side of fsyscall
protocol for Android, you will be able to use your Android tablet like a FreeBSD
machine.

Structure
=========

This section explains modules of fsyscall and how they work.

Hub system
----------

One feature of Unix is fork(2). An application can do one or more fork(2) to use
helper applications. To support this feature, fsyscall use HUBs.

.. image:: structure.png

A master machine includes:

1. One or more master processes. These are applications itself. One of them is
   what a user started. Rest of them are forked processes from the first one or
   its children (All of them uses the kernel module fmaster.ko. It will be
   explained later).
2. One MASTER HUB whose name is fmhub (Fsyscall Master HUB). One of its roles is
   sending messages from master processes to the slave machine with appening
   pid. A master hub also receives messages from the slave machine. It
   distributes a message to a destination processe which is specified in the
   message.

A slave machine includes:

1. One or more slave processes. One slave process is for one master process. A
   slave process does system call for its master process in the slave machine.
   If its master process did fork(2), the slave process also does fork(2). The
   new slave process is for the new master process. Name of the executable for
   slave process is fslave (Fsyscall SLAVE).
2. One SLAVE HUB whose name is fshub (Fsyscall Slave HUB). Its job is the same
   as a master hub -- sending messages from slave processes to the master
   machine, and distributing messages from the master machine.

Master processes and slave processes do not know about hubs. They think that
they are directly connected.

.. attention:: fork(2) for fsyscall is not implemented yet (2013-04-18).

Master process with fmaster.ko
------------------------------

Any ELF binaries are available for fsyscall without any modifications. All
mechanism is in fmaster.ko which is a kernel module.

fmaster.ko includes a system call entry table. Some entries are same as these of
original FreeBSD kernel. Rest of these are special entries for fsyscall. In such
special entries, a system call request is serialized and sent to a slave through
a master hub.

fmaster.ko does not send all requests. For example, an executable often needs
one or more libraries such as libc.so. These libraries must be opened in the
master machine because these will be mmap(2)'ed later, and because these must
have binary compatibility with the executable. So fmaster.ko opens such
libraries in the master machine. Since other files are opened in the slave
machine, fmaster.ko knows which file descriptor is on the slave, or on the
master. If an application requests to mmap(2) with a file descriptor, fmaster.ko
accepts the request only when the file descriptor is in the master machine (The
request is rejected when the file descriptor is in the slave).

.. image:: open_file.png

Master hub (fmhub)
------------------

Main role of fmhub is transfering messages from/to master processes.

Additionaly, fmhub has one more important role. That is sending signal to master
processes. If a user signals one of slave processes, fslave send signal
information to the master machine. When fmhub receives the message, it send the
same signal to the corresponding master process instead of the user.

.. image:: signal.png

.. attention:: Signal handling is not implemented yet (2013-04-18).

Slave hub (fshub)
-----------------

All fshub does is transfering messages as described in the above section. fshub
is a simple application.

Slave process (fslave)
----------------------

A slave process works as ordered by a master process. It does system calls
actually with sending the results.

Restrictions
============

fsyscall cannot execute an application which needs mmap(2).
-----------------------------------------------------------

As described above, a master process opens libraries in the master machine. But
if the application does mmap(2) for a non-library file, it fails. Because there
are no ways to share memory with the slave machine (The file may be mmap(2)'ed
in the slave machine by another non-fsyscall process).

Thread
------

The current implementation does not handle threads. The author is guessing that
lock of connection between master process and master hub is needed.

Problems
========

fsyscall has over 1,000 problems.

1. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.
#. Security. fslave must have access control mechanism.

Download
========

Tar balls (fsyscall-*x.y.z*.tar.xz) are available in `the author's
repository <http://neko-daisuki.ddo.jp/~SumiTomohiko/repos/index.html>`_.

Requirements
============

fsyscall works on FreeBSD 9.1.

How to compile
==============

Requirements
------------

To build fsyscall, you need

* `Python <http://www.python.org/>`_ 3.3
* `nasm <http://www.nasm.us/>`_ 2.10.3

Generate declarations of system call entry
------------------------------------------

First of all, you must generate system call declarations. Do the following
command at the top directory of the source tree::

    $ (cd fmaster/sys/fmaster && make)

Generate source code
--------------------

Large parts of fsyscall implementation are automatically generated with the
following command::

    $ python3 tools/makesyscalls.py

Compile a kernel
----------------

Compiling fmaster.ko needs a header file
(/usr/obj/usr/src/sys/GENERIC/includes/opt_global.h) which is generated in
compiling a kernel::

    $ (cd /usr/src && make -j4 buildkernel)

If you are using your own kernel, please change `KERNBUILDDIR` in
fmaster/Makefile::

    KERNBUILDDIR=	/usr/obj/usr/src/sys/GENERIC

Compile fsyscall
----------------

Now is the time to compile fsyscall::

    $ make

You will get

* fmaster/fmaster.ko
* fmhub/fmhub
* fshub/fshub
* fslave/fslave

Install fsyscall
----------------

Please install them by manually. fmaster.ko and fmhub must be installed into a
master machine. fshub and fslave must be installed into a slave machine. fmhub,
fshub and fslave must be in one directory of $PATH::

    master$ ln -s $PWD/fmhub/fmhub /usr/local/bin

::

    slave$ ln -s $PWD/fshub/fshub /usr/local/bin
    slave$ ln -s $PWD/fslave/fslave /usr/local/bin

Test
----

run_tests can run all tests::

    $ sudo kldload fmaster/fmaster.ko
    $ sync; sync; sync
    $ ./run_tests

How to use
==========

kldload fmaster.ko
------------------

First of all, you must do::

    $ sudo kldload fmaster/fmaster.ko

Use applications using fsyscall
-------------------------------

fsyscall does not have any functions to connect a master machine with a slave
machine. If you hope to use your machine as a slave, you can use nexec_.

.. attention:: There are no applications to use a machine as a master yet
    (2013-04-18).

Libraries starting fsyscall
---------------------------

If you want to write an application using fsyscall, you can use
fsyscall_start_master() function in lib/start_master/libstart_master.a to start
master side. You can also use fsyscall_start_slave() function in
lib/start_master/libstart_master.a.

Anything else
=============

License
-------

fsyscall is under `the MIT license <https://github.com/SumiTomohiko/fsyscall2/blob/master/COPYING.rst#mit-license>`_.

GitHub repository
-----------------

GitHub repository of fsyscall is https://github.com/SumiTomohiko/fsyscall2.

Author
------

The author of fsyscall is
`Tomohiko Sumi <http://neko-daisuki.ddo.jp/~SumiTomohiko/index.html>`_.

About cliparts in this documentation
------------------------------------

Some cliparts in this documentation came from other websites.

|internet-cloud| |chieftec_case| |people_computer| |jcartier_binary_file|

.. |internet-cloud| image:: internet-cloud.png
    :align: middle
    :target: http://openclipart.org/detail/152311/internet-cloud-by-b.gaultier
.. |chieftec_case| image:: chieftec_case.png
    :align: middle
    :target: http://openclipart.org/detail/78457/chieftec-computer-case-by-bocian
.. |people_computer| image:: people_computer.png
    :align: middle
    :target: http://openclipart.org/detail/37129/personnage_ordinateur-by-antoine
.. |jcartier_binary_file| image:: jcartier_binary_file.png
    :align: middle
    :target: http://openclipart.org/detail/17317/binary-file-by-jcartier

.. vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
