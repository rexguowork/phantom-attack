# Phantom Attack (v3): Evading System Call Monitoring without userfaultfd
Previously we have presented phantom attack v1 and v2. More details: 
[Phantom v1 and v2@Defcon POC code repo](https://raw.githubusercontent.com/rexguowork/phantom-attack/main/README.md)

Phantom v1 is a powerful TOCTOU attack because it should be able to bypass all 
syscall monitoring that contains string arguments. Since v1 relies on 
userfaultfd system calls. There are two limitations:
1. It makes detection possible because userfaultfd system call can be monitored
2. The attack is likely not work in container environments since the default container seccomp profile 
blocks userfaultfd and most container deployment uses such policy. 

We exploited the fact that if the syscall takes a long time to complete, the 
attacker has ample time to change the syscall arguments without using userfaultfd.

We prove such attacks are possible on two classes of system calls:
1. Networking
2. File (when FuseFS is used)

NOTE that the fundamental observation is syscall can be blocked and any method
that can make syscall block allows similar bypass.

## Attack Description

### Attacks on Networking Syscalls
Take connect syscall as an example. Say sysdig/pdig sits on the client machine
and client software connects to the server (a command and control machine owned
by the attacker). The server can drop a few SYN packets before accepting it.
This will cause the client to do TCP SYN retries with exponential back off.
With a few SYN drops, we are able to give the client program enough time to
overwrite the connect syscall argument. Similarly, you can trigger network
retry and manipulate the timing of other networking syscalls. Our attack works
on the sysdig agent and also pdig running on fargate.

### Attacks on File Syscalls
Following similar ideas as our connect syscall attack. What if we can delay
file related syscalls? This happens to be the case if the system uses FUSE.
There are a few popular projects such as SSHFS, S3FS, etc. GCP also supports
FUSE in their k8s. 
With FUSE, we are able to overwrite the openat syscall argument. Similarly,
other file related syscalls are also vulnerable. Our attack works on the sysdig
agent and also pdig running on fargate.

## Evaluation

### Attacks on Networking Syscalls (Sysdig/Pdig)

#### Set up 
1. For attacking sysdig, sysdig can run one a VM, bare metal or a container.
   This machine is the client machine.
   For attacking pdig, pdig runs on serverless form factor such as a fargate container. 
   Fargate container with pdig as the client machine.
2. a C2 server, e.g., an EC2 instance. C2 EC2 runs the ebpf program.

#### Plan
Malicious client software on sysdig/pdig installed machine is going to connect 
to the server software on C2 EC2. sysdig/pdig will report the wrong IP address because C2 EC2
has a ebpf program that drops the first 5 syn packets from anywhere (can be even 
less than 5, still investigating, but does not impact the feasibility of the attack). The linux
TCP/IP stack is going to keep retrying with exponential delay for every dropped
syn packet. This is going to create enough delay for the program. 


#### Steps to reproduce:

1. move the server folder to the server
2. move the client folder to the client, i.e., where sysdig/pdig is running.
   For pdig, it will be the fargate container.

3. login the C2 server:
4. Run the ebpf program to drop packets. Replace the --dev with the
   network interface on your C2 machine. This should be the interface that
talks to the client machine. In order to compile the ebpf program, check the
dependency instruction file at server/ebpf/setup_dependencies.org

```console
$ cd networking/server/ebpf/traffic_drop
$ make
$ sudo ./xdp_load_and_stats --dev ens33 --force --progsec xdp_main1 --skb-mode -D 3
```
`-D N` specifies the Nth packet to accept for every N packets
if you wnat to turn off the ebpf program
$ sudo ip link set dev eth0 xdp off

4. run the chat server
```console
$ cd networking/server
$ make
$ ./tcp_server
```
NOTE: 
traffic_drop allows one to pass in an argument to control the number of packets
to drop. By default, it will accept the 3rd SYN packet for every three SYN packets.

5. login to the client machine (fargate container in the pdig's case)
6. run the phantomv3_tcp_client. You will need to change the server IP address
   hardcoded in the client software.
```console
$ cd networking/client
$ make
$ ./phantomv3_tcp_client
```
For pdig, replace the last command with:
```console
$ ./pdig -a ./phantomv3_tcp_client
```
if everything works well, the tcp chat client and server should be able to communicate with each
other and sysdig/pdig will report the client is connecting to the 1.1.1.1 IP
address which is chosen by the client software arbitrarily.


NOTE:
phantomv3_connect.c is a simple POC to demonstrate the attack work. It only
demonstrate that if the three way handshake is delayed, then the attack
essentially will work. The chat client is more for a full blown demo to show
the attacker is able to communicate to the C2 server after the tcp handshake.

### Attacks on File Syscalls (Sysdig/Pdig)

#### Set up 
1. For attacking sysdig, sysdig can run one a VM, bare metal or a container.
   This machine is the client machine.
   For attacking pdig, pdig runs on serverless form factor such as a fargate container. 
   Fargate container with pdig as the client machine.
2. a FUSE file target. In our experiment, we use an ssh server. 

NOTE: To allow FuseFS in fargate, it requires the fargate to run on an EC2 and
run as privileged container. GCP claims to support FUSE natively in their k8s
cluster, but we are in the process of verifying this.


#### Plan
Malicious client software on sysdig/pdig installed machine is going to mount
sshfs from the server machine. sysdig/pdig will report the wrong file path because 
the round trip time to access the ssh server using SSHFS is long enough that
the client software has enough time to change the user space syscall arguments.
The intuition is essentially similar to the attack on networking calls, i.e.,
network delay is much slower than system call execution time.

#### Steps to reproduce:

1. Install ssh server on the server side
2. Install sshfs on the client side. Can follow this [tutorial](https://www.digitalocean.com/community/tutorials/how-to-use-sshfs-to-mount-remote-file-systems-over-ssh) 
3. Once you make sure the sshfs is working, left the sshfs connected
4. Run the commands below:

```console
$ cd file
$ make
$ ./phantomv3_openat
```
For pdig, replace the last command with:
```console
$ ./pdig -a ./phantomv3_openat
```

If everything works, you should be able to see the client software opens 
`/root/droplet/malicious_file`
But sysdig/pdig reports
`/root/droplet/benign_file`
