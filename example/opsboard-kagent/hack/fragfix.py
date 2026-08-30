import sys, yaml
path, name, add_redis = sys.argv[1], sys.argv[2], (len(sys.argv) > 3 and sys.argv[3] == "redis")
d = yaml.safe_load(open(path))
d["metadata"]["name"] = name
if add_redis:
    op = d["spec"].setdefault("opens", [])
    have = {o.get("path") for o in op}
    # BGSAVE writes /data/temp-<childpid>.rdb and reads /proc/<childpid>/smaps;
    # the child PID varies every save -> wildcard both so R0002 stops firing.
    for p, fl in (("/data/⋯", ["O_WRONLY", "O_CREAT", "O_TRUNC", "O_LARGEFILE", "O_RDONLY"]),
                  ("/proc/⋯/smaps", ["O_RDONLY", "O_LARGEFILE"])):
        if p not in have:
            op.append({"path": p, "flags": fl})
yaml.safe_dump(d, open(path, "w"), sort_keys=False, allow_unicode=True)
print("  wrote", name, "opens=", len(d["spec"].get("opens", [])))
