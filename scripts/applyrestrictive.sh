
echo "Creating restrictive ApplicationProfile to catch file access attacks..."
cat <<'EOF' > webapp-profile-strict.yaml
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata:
  name: webapp-profile-strict
  namespace: webapp
spec:
  architectures:
  - amd64
  containers:
  - capabilities:
    - CAP_DAC_OVERRIDE
    - CAP_SETGID
    - CAP_SETUID
    endpoints: null
    execs:
    - args:
      - /usr/bin/dirname
      - /var/run/apache2
      path: /usr/bin/dirname
    - args:
      - /usr/bin/dirname
      - /var/lock/apache2
      path: /usr/bin/dirname
    - args:
      - /usr/bin/dirname
      - /var/log/apache2
      path: /usr/bin/dirname
    - args:
      - /bin/mkdir
      - -p
      - /var/run/apache2
      path: /bin/mkdir
    - args:
      - /usr/local/bin/apache2-foreground
      path: /usr/local/bin/apache2-foreground
    - args:
      - /bin/rm
      - -f
      - /var/run/apache2/apache2.pid
      path: /bin/rm
    - args:
      - /bin/mkdir
      - -p
      - /var/log/apache2
      path: /bin/mkdir
    - args:
      - /bin/mkdir
      - -p
      - /var/lock/apache2
      path: /bin/mkdir
    - args:
      - /usr/sbin/apache2
      - -DFOREGROUND
      path: /usr/sbin/apache2
    - args:
      - /usr/local/bin/docker-php-entrypoint
      - apache2-foreground
      path: /usr/local/bin/docker-php-entrypoint
    identifiedCallStacks: null
    imageID: ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b
    imageTag: ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b
    name: mywebapp-app
    opens:
    - flags:
      - O_APPEND
      - O_CLOEXEC
      - O_CREAT
      - O_DIRECTORY
      - O_NONBLOCK
      - O_RDONLY
      - O_RDWR
      - O_WRONLY
      path: /var/www/*
    - flags:
      - O_APPEND
      - O_CLOEXEC
      - O_CREAT
      - O_DIRECTORY
      - O_NONBLOCK
      - O_RDONLY
      - O_RDWR
      - O_WRONLY
      path: /var/run/apache2/*
    - flags:
      - O_APPEND
      - O_CLOEXEC
      - O_CREAT
      - O_DIRECTORY
      - O_NONBLOCK
      - O_RDONLY
      - O_RDWR
      - O_WRONLY
      path: /var/log/apache2/*
    - flags:
      - O_APPEND
      - O_CLOEXEC
      - O_CREAT
      - O_DIRECTORY
      - O_NONBLOCK
      - O_RDONLY
      - O_RDWR
      - O_WRONLY
      path: /var/lock/apache2/*
    - flags:
      - O_RDONLY
      path: /usr/*
    - flags:
      - O_RDONLY
      path: /lib/*
    rulePolicies: {}
    seccompProfile:
      spec:
        defaultAction: ""
    syscalls:
    - accept4
    - access
    - arch_prctl
    - bind
    - brk
    - capget
    - capset
    - chdir
    - chmod
    - clone
    - close
    - close_range
    - connect
    - dup2
    - dup3
    - epoll_create1
    - epoll_ctl
    - epoll_pwait
    - execve
    - exit
    - exit_group
    - faccessat2
    - fcntl
    - fstat
    - fstatfs
    - futex
    - getcwd
    - getdents64
    - getegid
    - geteuid
    - getgid
    - getpgrp
    - getpid
    - getppid
    - getrandom
    - getsockname
    - gettid
    - getuid
    - ioctl
    - listen
    - lseek
    - mkdir
    - mmap
    - mprotect
    - munmap
    - nanosleep
    - newfstatat
    - openat
    - openat2
    - pipe
    - prctl
    - prlimit64
    - read
    - recvfrom
    - recvmsg
    - rename
    - rt_sigaction
    - rt_sigprocmask
    - rt_sigreturn
    - select
    - sendto
    - set_robust_list
    - set_tid_address
    - setgid
    - setgroups
    - setsockopt
    - setuid
    - sigaltstack
    - socket
    - stat
    - statfs
    - statx
    - sysinfo
    - tgkill
    - times
    - tkill
    - umask
    - uname
    - unknown
    - unlinkat
    - wait4
    - write
status: {}
EOF
echo "Created webapp-profile-strict.yaml"
echo

echo "Applying restrictive ApplicationProfile..."
kubectl apply -f webapp-profile-strict.yaml
echo "Restrictive ApplicationProfile applied successfully"
echo

echo "Updating deployment to use restrictive profile..."
kubectl patch deployment webapp-mywebapp -n webapp --type merge -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"webapp-profile-strict"}}}}}'
echo "Label updated to use webapp-profile-strict"
echo

echo "Restarting deployment to pick up the restrictive profile..."
kubectl rollout restart deployment webapp-mywebapp -n webapp
echo "Deployment restarted with restrictive profile"
echo

echo "Waiting for rollout to complete..."
kubectl rollout status deployment webapp-mywebapp -n webapp
echo

echo "Verifying the restrictive profile is being used..."
kubectl logs -l app=node-agent -n honey --tail=50 | grep "webapp-profile-strict" || echo "Profile not found in recent logs yet. It may take a moment."
echo
