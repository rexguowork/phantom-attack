# Phantom Attack: Evading System Call Monitoring

Phantom attack is a collection of attacks that evade Linux system call
monitoring. A user mode program does not need any special privileges or
capabilities to reliably evade system call monitoring using Phantom attack by
exploiting insecure tracing implementations.

After adversaries gain an initial foothold on a Linux system, they typically
perform post-exploitation activities such as reconnaissance, execution,
privilege escalation, persistence, etc. It is extremely difficult if not
impossible to perform any non-trivial adversarial activities without using
Linux system calls.

Security monitoring solutions on Linux endpoints typically offer system call
monitoring to effectively detect attacks. Modern solutions often use either
ebpf-based programs or kernel modules to monitor system calls through
tracepoint and/or kprobe. Any adversary operations including abnormal and/or
suspicious system calls reveal additional information to the defenders and can
trigger detection alerts.

This github project hosts the POC code for Phantom Attack. More details can be
found in our [DEFCON 29 talk](https://defcon.org/html/defcon-29/dc-29-speakers.html#guo).

## Files 
```bash
.
├── phantom_v1 
│   ├── attack_connect.c ---------------------------# phantom v1 attack on connect
│   ├── attack_openat.c  ---------------------------# phantom v1 attack on openat
│   ├── Makefile 
│   └── run.sh           ---------------------------# add CAP_SYS_NICE for binary (e.g., openat)
├── phantom_v2
│   └── run.sh           ---------------------------# phantom v2 attack on file link
├── README.md
└── LICENSE
```

attack_connect.c:
POC attack code on evading the connect call monitoring
The attack program connect to 1.1.1.1, it tries to make the agent thinks it is
connecting to any benign looking IP. E.g., 13.107.42.14


attack_openat.c:
POC attack code on evading the openat call monitoring
The attack program opens file with name "malicious_file" in the current working
directory, it tries to make agent thinks it is opening a benign looking file with name "benign_file". 


## Getting Started:

### To compile:
`$ cd phantom_v1
 $ make`


### Phantom v1 attack on connect system call 

1. open one terminal and use tcpdump to monitor the traffic to port 80. Change the
   ethernet interface based on your machine in the command below

`$ sudo tcpdump -i ens33 port 80`


2. run the syscall monitoring software to monitor connect call


3. run the attack and see the tcpdump will report traffic to 1.1.1.1 while
   sysdig open source agent will report attack_connect program connect to 13.107.42.14

`$ ./attack_connect`


### Phantom v1 attack on openat system call 

You can run the attack manually and inspect the file artifact and
system call monitoring software results manually. Since sometimes the overwrite thread writes
the filename too fast, syscall will only opens the benign file. So you may want
to run the attack in a loop to automatically check the results for multiple
runs.

1. run system call monitoring software and monitor openat syscall

2. run the attack_openat. Need CAP_SYS_NICE

`$ ./attack_openat`

3. check whether the file created is diff from the file reported by the agent

### Phantom v2 attack on file link

`$ cd phantom_v2
 $ ./run.sh`
