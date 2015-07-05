
Signal handling in fsyscall
***************************

The basic strategy
==================

The basic strategy of signal handling is sending all signals to the master, even
if the signal is ignored by the master.

Problem
=======

The current implementation of fslave's signal handling has one problem. If a
system call blocking for long time (or indefinitely) such as poll(2), select(2)
or kevent(2) is requested, and if a signal is delivered in running the system
call, the fslave does not send the SIGNALED command to the master.

To fix this problem, fsyscall needs to have a special thread to handle signal.

sigaction(2)
============

The fslave had sigaction(2) implementation. You can get it with checking out
the commit 1bd5ab12572d9bccba8c018a1179fec20fb3ef1d.

.. vim: tabstop=2 shiftwidth=2 expandtab softtabstop=2 filetype=rst
