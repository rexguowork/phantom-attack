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
found in :
1. [DEFCON 29 website](https://defcon.org/html/defcon-29/dc-29-speakers.html#guo) 
2. [DEFCON 29 slides](Phantom_attack_evading_system_call_monitoring.pdf)
3. [DEFCON 29 youtube recording](https://www.youtube.com/watch?v=yaAdM8pWKG8&ab_channel=DEFCONConference)

## Evaluation 

### Target Software
[Falco](https://github.com/falcosecurity/falco) < v0.29.1 

[Tracee](https://github.com/aquasecurity/tracee) <= v0.4.0 

Note that Falco's mitigation is detecting userfaultfd syscall from non-root user, so you may still be able to perform the TOCTOU on newer versions but it will get detected because of the use of userfaultfd. We did not evaluate newer version of Tracee and they may still be vulnerable.


### Platform
Phantom Attack was tested on the following configurations:

| OS                 | Hypervisior            | CPU Cores |
| -------------      | ---------------------- | ----------|
| Ubuntu 20.04       | wmware workstation pro | 2 cores   |
| Ubuntu 18.04       | vmware workstation pro | 4 cores   |

If you are testing on 2 cores, remember to change the CPU mask in the POC.

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
├── Phantom attack evading system call monitoring.pdf ---# DEFCON 29 slides
├── README.md
└── LICENSE
```

attack_connect.c:
POC attack code on evading the connect call monitoring
The attack program connect to 1.1.1.1, it tries to make the agent thinks it is
connecting to any benign looking IP. E.g., 13.107.42.14. The interrupt used is IPI interrupt.

attack_openat.c:
POC attack code on evading the openat call monitoring
The attack program opens file with name "malicious_file" in the current working
directory, it tries to make agent thinks it is opening a benign looking file with name "benign_file". 
The interrupt used is hardware interrupt so you need to identify the CPU core that handles the ethernet hardware interrupt on your set up and change the VICTIM_CPU accordingly.


## Getting Started:

### To compile:
```console
$ cd phantom_v1
$ make
```

### Phantom v1 attack on connect system call 

1. open one terminal and use tcpdump to monitor the traffic to port 80. Change the
   ethernet interface based on your machine in the command below

```console
$ sudo tcpdump -i ens33 port 80
```


2. run the syscall monitoring software to monitor connect call


3. run the attack and see the tcpdump will report traffic to 1.1.1.1 while
   sysdig open source agent will report attack_connect program connect to 13.107.42.14

`$ ./attack_connect`


### Phantom v1 attack on openat system call 

You can run the attack manually and inspect the file artifact and
system call monitoring software results manually. 

NOTE: Since sometimes the overwrite thread writes the filename faster than the kernel thread, syscall will only opens the benign file. 
So you may want to run the attack in a loop to automatically check the results for multiple runs as demonstrated in the DEFCON talk.

1. run system call monitoring software and monitor openat syscall

2. You will most likely need CAP_SYS_NICE

`$ ./run.sh attack_openat`

3. Run the attack
`$ ./attack_openat`

4. check whether the file created is diff from the file reported by the agent

### Phantom v2 attack on file link

1. run system call monitoring software and monitor openat syscall

2. run commands below

`$ cd phantom_v2`

`$ ./run.sh`
