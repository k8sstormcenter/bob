#!/bin/bash
set -e

rm -rf bobctl
git clone https://github.com/k8sstormcenter/bobctl.git
cd bobctl
git checkout test/localtestbuild



read -p "Please enter the image tag for storage : " IMAGE_TAG
read -p "Please enter the image tag for node-agent: " NIMAGE_TAG
echo


VALUES_FILE="kubescape/values.yaml"
echo "Updating $VALUES_FILE..."

NEW_CONTENT=$(cat <<EOF
storage:
  image:
    repository: ghcr.io/k8sstormcenter/storage
    tag: ${IMAGE_TAG}

nodeAgent:
  image:
    repository: ghcr.io/k8sstormcenter/node-agent
    tag: ${NIMAGE_TAG}
  config:
    maxLearningPeriod: 10m
    learningPeriod: 5m
    updatePeriod: 10000m
    ruleCooldown:
      ruleCooldownDuration: 0h
      ruleCooldownAfterCount: 1000000000
      ruleCooldownOnProfileFailure: false
      ruleCooldownMaxSize: 20000
capabilities:
  runtimeDetection: enable
  networkEventsStreaming: disable
alertCRD:
  installDefault: true
  scopeClustered: true
clusterName: bobexample
ksNamespace: honey
excludeNamespaces: "kubescape,kube-system,kube-public,kube-node-lease,kubeconfig,gmp-system,gmp-public,storm,lightening,cert-manager,kube-flannel,ingress-nginx,olm,px-operator,honey"
linuxAudit:
  enabled: true
EOF
)

awk -v new_content="$NEW_CONTENT" '
  BEGIN {p=1}
  /^storage:/ {print new_content; p=0}
  {if(p)print}
' "$VALUES_FILE" > "${VALUES_FILE}.tmp" && mv "${VALUES_FILE}.tmp" "$VALUES_FILE"

echo "$VALUES_FILE has been updated successfully."
echo


echo "Running 'make kubescape'..."
make kubescape
echo "'make kubescape' finished."
echo


echo "Running 'make helm-install-no-bob'..."
make helm-install-no-bob

make fwd

echo "Waiting for ApplicationProfile to be ready..."
while ! kubectl get applicationprofiles.spdx.softwarecomposition.kubescape.io replicaset-webapp-mywebapp-c8bdd6944 -n webapp &> /dev/null; do
  echo "Waiting for ApplicationProfile replicaset-webapp-mywebapp-c8bdd6944 in namespace webapp..."
  sleep 5
done

echo "ApplicationProfile is ready. Exporting to webapp-profile.yaml..."
kubectl get applicationprofiles.spdx.softwarecomposition.kubescape.io replicaset-webapp-mywebapp-c8bdd6944 -n webapp -o yaml > webapp-profile.yaml
echo "ApplicationProfile exported successfully to webapp-profile.yaml"
echo

echo "Creating user-defined ApplicationProfile (webapp-profile-merged.yaml)..."
cat <<'EOF' > webapp-profile-merged.yaml
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata:
  name: webapp-profile
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
      - O_EXCL
      - O_NONBLOCK
      - O_RDONLY
      - O_RDWR
      - O_WRONLY
      path: /*
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
echo "Created webapp-profile-merged.yaml"
echo

echo "Applying user-defined ApplicationProfile..."
kubectl apply -f webapp-profile-merged.yaml
echo "ApplicationProfile applied successfully"
echo

echo "Adding label to deployment to use the new profile..."
kubectl patch deployment webapp-mywebapp -n webapp --type merge -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"webapp-profile"}}}}}'
echo "Label added successfully"
echo

echo "Restarting deployment to pick up the new profile..."
kubectl rollout restart deployment webapp-mywebapp -n webapp
echo "Deployment restarted"
echo

echo "Waiting for rollout to complete..."
kubectl rollout status deployment webapp-mywebapp -n webapp
echo

echo "Verifying the new profile is being used..."
kubectl logs -l app=node-agent -n honey --tail=50 | grep "webapp-profile" || echo "Profile not found in recent logs yet. It may take a moment."
echo

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

echo "Running file open attacks to test detection..."
WEBAPP_POD=$(kubectl get pod -n webapp -l app=mywebapp-app -o jsonpath='{.items[0].metadata.name}')
echo "Testing with pod: $WEBAPP_POD"
echo

echo "Test 1: Reading /etc/apache2/apache2.conf (should be blocked/alerted)..."
kubectl exec -n webapp $WEBAPP_POD -- cat /etc/apache2/apache2.conf || echo "Command failed as expected"
echo

echo "Test 2: Creating file in /tmp (should be blocked/alerted)..."
kubectl exec -n webapp $WEBAPP_POD -- touch /tmp/pwned || echo "Command failed as expected"
echo

echo "Test 3: Writing to /tmp (should be blocked/alerted)..."
kubectl exec -n webapp $WEBAPP_POD -- sh -c 'echo hi > /tmp/pwned' || echo "Command failed as expected"
echo

echo "Test 4: Reading from /tmp (should be blocked/alerted)..."
kubectl exec -n webapp $WEBAPP_POD -- cat /tmp/pwned || echo "Command failed as expected"
echo

echo "Test 5: Deleting file in /tmp (should be blocked/alerted)..."
kubectl exec -n webapp $WEBAPP_POD -- rm /tmp/pwned || echo "Command failed as expected"
echo

echo "Checking for alerts in Kubescape logs..."
kubectl logs -l app=node-agent -n honey --tail=100 | grep -i "alert\|violation\|denied\|webapp-profile-strict" || echo "No alerts found yet. They may take a moment to appear."
echo






