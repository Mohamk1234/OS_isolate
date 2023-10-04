# OS_isolate
A program which provides OS-level sandboxing using namespaces(PID, Net, Mount). Seccomp BPF is used to prevent a process from invoking certain system calls. 

# usage
./os_isolate [-b binary]

-b  path to the binary that will be executed in the sandbox

As an example, the following invocation of os_isolate will run a new bash
shell that will be isolated from other processes running in the program:

./os_isolate -b /bin/bash

