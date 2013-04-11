
fsyscall
********

Description
===========

fsyscall is a system to transfer system call requests from applications on
FreeBSD to another process through file descriptors. The expected usage is using
applications on FreeBSD from other non-FreeBSD or powerless machines. For
example, Android tablets will be able to use applications on FreeBSD by
fsyscall.

Master and slave
================

.. image:: overview_of_system_call_flow.png

fsyscall transfers system calls handling files.
===============================================

.. vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
