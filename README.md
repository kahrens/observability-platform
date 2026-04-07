On a new machine, first generate vmlinux.h, otherwise just:

make vmlinux.h   # only needed once per machine (or after kernel upgrade)
make run         # generates BPF bindings, builds, and runs with sudo


Or broken out individually:

make vmlinux.h   # generate probes/vmlinux.h from running kernel BTF
make generate    # compile BPF C + generate Go bindings via bpf2go
make build       # go build → ./collector binary
sudo ./collector # run (or just: make run)
