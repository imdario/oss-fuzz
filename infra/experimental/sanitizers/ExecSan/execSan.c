/*
 * Copyright 2022 Google LLC

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *      http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
/* A detector that uses ptrace to identify shell injection vulnerabilities. */

#define _POSIX_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

void tracee_process(char **argv) {
  /* Child */
  printf("%d: Tracee\n", getpid());
  ptrace(PTRACE_TRACEME, 0, 0, 0);
  execv(argv[1], argv + 1);
  exit(0);
}

void tracer_process(pid_t tracee_pid) {
  /* Parent */
  waitpid(tracee_pid, NULL, 0);
  printf("%d: Tracer\n", getpid());

  struct user_regs_struct regs;
  int i = 0;
  int status = -1;

  // Ensures that the tracee will never escape
  long data = PTRACE_O_EXITKILL
      | PTRACE_O_TRACEFORK
      | PTRACE_O_TRACEVFORK
      | PTRACE_O_TRACECLONE
//      | PTRACE_O_TRACEEXEC
      ;
  ptrace(PTRACE_SETOPTIONS, tracee_pid, NULL, data);

  while (kill(tracee_pid, 0) != -1) {
    i++;
    printf("=== %03d ===\n", i);

    ptrace(PTRACE_SYSCALL, tracee_pid, NULL, NULL);
    status = waitpid(tracee_pid, NULL, 0);

    ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs);
    printf("%d: %lld\n", tracee_pid, regs.orig_rax);

    ptrace(PTRACE_SYSCALL, tracee_pid, NULL, NULL);
    status = waitpid(tracee_pid, NULL, 0);

    pid_t child_pid = -1;

    ptrace(PTRACE_GETEVENTMSG, tracee_pid, 0, &child_pid);
    status = waitpid(child_pid, NULL, 0);

    printf("%d: Child\n", child_pid);
    printf("Exec: %d\n", status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8)));
    printf("CLONE: %d\n", status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)));
    printf("FORK: %d\n", status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)));
    printf("VFORK: %d\n", status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)));
    printf("WIFSTOPPED(status): %d\n", WIFSTOPPED(status));
    printf("WSTOPSIG(status): %d\n", WSTOPSIG(status));

    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    status = waitpid(child_pid, NULL, 0);
    printf("%d: %lld\n", child_pid, regs.orig_rax);

    if (regs.orig_rax == 56) {
      printf("%d: %lld\n", child_pid, regs.orig_rax);
      tracee_pid = child_pid; //keep the parent pid
    }

    if (regs.orig_rax == 59) {
      printf("===BUG DETECTED: Shell injection===\n");
    }


//    pid_t pid2;
//    ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &pid2);
//    printf("%d: PID2\n", pid2);
//    printf("%d: %lld\n", pid2, regs.orig_rax);

//    ptrace(PTRACE_CONT, child_pid, 0, 0);

    if (status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))) {
      ptrace(PTRACE_GETEVENTMSG, tracee_pid, 0, &child_pid);
      ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
      printf("%d: %lld\n", child_pid, regs.orig_rax);
      ptrace(PTRACE_CONT, child_pid, 0, 0);
    }

    if (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
      ptrace(PTRACE_GETEVENTMSG, tracee_pid, 0, &child_pid);
      ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
      printf("%d: %lld\n", child_pid, regs.orig_rax);
      ptrace(PTRACE_CONT, child_pid, 0, 0);
    }

    if (status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))) {
      ptrace(PTRACE_GETEVENTMSG, tracee_pid, 0, &child_pid);
      ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
      printf("%d: %lld\n", child_pid, regs.orig_rax);
      ptrace(PTRACE_CONT, child_pid, 0, 0);
    }


    if (status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) {
      ptrace(PTRACE_GETEVENTMSG, tracee_pid, 0, &child_pid);
      ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
      printf("%d: %lld\n", child_pid, regs.orig_rax);
      ptrace(PTRACE_CONT, child_pid, 0, 0);
    }

  }
}

int main(int argc, char **argv) {
  if (argc <= 1) {
    printf("Expecting at least one arguments, received %d", argc - 1);
    exit(1);
  }

  pid_t pid = fork();
  switch (pid) {
    case -1:
      printf("Failing to fork()");
      exit(1);
    case 0:
      // Child
      tracee_process(argv);
      break;
    default:
      // Parent
      tracer_process(pid);
  }
}
