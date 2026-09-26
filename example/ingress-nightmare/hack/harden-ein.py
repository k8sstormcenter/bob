#!/usr/bin/env python3
import sys, pathlib

ein = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "ein")
exp = ein / "nginx-ingress" / "exploit.go"
src = exp.read_text()

src = src.replace(
    "\tvar wg sync.WaitGroup\n\tsuccessFlag := false\n",
    "\tvar wg sync.WaitGroup\n\tsem := make(chan struct{}, 256)\n\tsuccessFlag := false\n",
)
src = src.replace(
    "\t\t\tgo func(pid, fd int) {\n\t\t\t\tdefer wg.Done()\n\t\t\t\tselect {\n",
    "\t\t\tgo func(pid, fd int) {\n\t\t\t\tdefer wg.Done()\n\t\t\t\tdefer func() { recover() }()\n\t\t\t\tsem <- struct{}{}\n\t\t\t\tdefer func() { <-sem }()\n\t\t\t\tselect {\n",
)
src = src.replace("gout.WithTimeout(100*time.Second)", "gout.WithTimeout(5*time.Second)")

exp.write_text(src)
ok = "sem := make(chan struct{}, 256)" in src and "defer func() { <-sem }()" in src and "gout.WithTimeout(100" not in src
print("harden-ein: ok" if ok else "harden-ein: FAILED to apply")
sys.exit(0 if ok else 1)
