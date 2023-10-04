#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <seccomp.h>


static char child_stack[1048576];

static int seccomp() {
    struct sock_filter filter[] = {
        /* Validate architecture */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

        /* Allow only specific syscalls */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        // allow read/write
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
      //   allow exit
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 0, 1),
        // allow execve
       BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        // deny everything else
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl");
        exit(EXIT_FAILURE);
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        perror("prctl");
        exit(EXIT_FAILURE);
    }
    return 0;
}

static int create_container(char *arg) {
 
 	system("./busybox-i686 ip link");
	system("ps aux");
	
	char *cmd[] = {arg, NULL};
	execv(arg, cmd);
	perror("exec");
	exit(EXIT_FAILURE);
}

static int child(void *args) {

	printf("childFunc(): PID  = %ld\n", (long) getpid());
	
	char *new_root = "/home/kali/Downloads/home/";
	chdir(new_root);
  
	if (chroot(new_root) < 0) {
        	perror("chroot");
        	exit(EXIT_FAILURE);
  	}

	
	char *mount_point = "/proc";

    	mkdir(mount_point, 0555);     
        if (mount("proc", mount_point, "proc", 0, NULL) < 0){
          printf("mounting error");
          exit(EXIT_FAILURE);
        }

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        perror("seccomp_init");
        exit(EXIT_FAILURE);
    }

    // add seccomp rules
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(chroot), 0) < 0) {
        perror("seccomp_rule_add chroot");
        exit(EXIT_FAILURE);
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mount), 0) < 0) {
        perror("seccomp_rule_add mount");
        exit(EXIT_FAILURE);
    }

    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        exit(EXIT_FAILURE);
    }
    
    // apply seccomp filter
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        exit(EXIT_FAILURE);
    }  
	create_container((char*)args);
	return (0);
}

int main(int argc, char **argv) {
	char *cmd = "/bin/bash";
	
	if ( argc == 3 )
		cmd = argv[2];
  	
  	if(unshare(CLONE_NEWNS) < 0){
  		perror("unshare");
  		exit(EXIT_FAILURE);
  	}
  	if (mount("/home/kali/Downloads/home/", "/", NULL, MS_BIND | MS_REC, NULL) < 0) {
        	perror("mount");
        	exit(EXIT_FAILURE);
  	}

  	pid_t child_pid = clone(child, child_stack+1048576, SIGCHLD | CLONE_NEWPID | CLONE_NEWNET, cmd);

  	printf("clone() = %ld\n", (long)child_pid);
  	waitpid(child_pid, NULL, 0);
  	return 0;
}