# eBPF Package Repository

The concept of a L3AF eBPF Package Repository is to create a location where eBPF Programs from any trusted party can be uploaded and made available for others to download. In the context of L3AF, we define an eBPF Package as a kernel space program with an optional, cooperative user space program.

All submissions will be manually reviewed and once approved, programs will be published in the eBPF Package Repository. Another important thing to note is that, initially, code submissions will need to conform to L3AF's eBPF program chaining mechanics. It is expected that contributors will include scripts (e.g. Dockerfile for build system images), and steps to build eBPF Programs locally (e.g. for x86_64 platforms).


## eBPF Programs

- [xdp-root](https://github.com/l3af-project/eBPF-Package-Repository/tree/main/xdp-root/)
- [tc-root](https://github.com/l3af-project/eBPF-Package-Repository/tree/main/tc-root/)
- [ratelimiting](https://github.com/l3af-project/eBPF-Package-Repository/tree/main/ratelimiting)
- [connection-limit](https://github.com/l3af-project/eBPF-Package-Repository/tree/main/connection-limit)
- [ipfix-flow-exporter](https://github.com/l3af-project/eBPF-Package-Repository/tree/main/ipfix-flow-exporter)
- [traffic-mirroring](https://github.com/l3af-project/eBPF-Package-Repository/tree/main/traffic-mirroring)
