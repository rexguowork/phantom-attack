# Phantom Attack (v4): Evading ptrace at sys_enter 
This attack demonstrates ways to bypass ptrace at sys_enter. We tested the
attack for a few file system related syscalls and it should work for all
syscalls due to how ptrace and seccomp are implmented.

pdig uses ptrace + seccomp redirect if it starts the monitored application, 
so pdig is not vulnerable to this attack when operating with this mode. 

When pdig attaches to a running app, it will use plain ptrace mode. This make
sense because if ptrace + seccomp direct is used, then the initial seccomp
filters set up by the application will not be evaluated. 

We demonstrate the attack for plain ptrace mode using a demo tracer. Interested 
reader can try it on pdig.

NOTE that the implication of this attack can also applies to malware 
sandboxes that relies on ptrace.

## Attack Description
The application being monitored will set up seccomp filters and then call
a syscall. The app will also create another thread to overwrite the userspace
memory which contains the syscall arguments. When the syscall executes, ptrace
will first read the initial arguments. Since the syscall needs to compute
seccomp profiles, the real syscall will get the overwritten arguments due to
the delay introduced by seccomp.

## Evaluation

### Attacks on Networking Syscalls (Sysdig/Pdig)

#### Set up 
1. a single machine


#### Steps to reproduce:

This attack is simple and we recommend just reading the run.sh and the code to
follow through. 

```console
$ make
$ ./run.sh 
```
