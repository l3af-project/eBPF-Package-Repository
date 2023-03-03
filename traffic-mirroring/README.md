Traffic Mirroring Tool (TMT)
=================
This repository contains an eBPF program that enables mirroring traffic from a host (source) to a remote host (collector) by using tc hooks.
Additional capabilities are provided with which traffic can be filtered based on standard parameters(source address, destination address, source port, remote port and protocol) at the localhost itself to save the bandwidth. Traffic is sent over GUE overlay to the remote host. GUE overlay has to be configured on local and remote ends as shown in the usage section.

Prerequisites
=================

_#Get the dependencies_
```
apt-get install libpcap-dev libcurl4-openssl-dev clang llvm
```
  

_#Get Linux source code to build our eBPF programs against_
```
git clone --branch v5.1 --depth 1 https://github.com/torvalds/linux.git /usr/src/linux
```
  

_# Create a ".config" file with default options from the current OS build config_
```
cd /usr/src/linux
make defconfig
```
_# [tc-root](../tc_root)_ : This is the root program that enables chaining of multiple eBPF programs on a single network interface. Download, build, and execute the tc-root program on the interface you want to mirror prior to proceeding to the next steps.


Installation
=================

_#Get the TMT repository_  
```
cd /usr/src/linux  
git clone https://github.com/l3af-project/eBPF-Package-Repository.git /usr/src/linux/samples/bpf/  
```

_# Build TMT_  
```
cd /usr/src/linux/samples/bpf/eBPF-Package-Repository/traffic-mirroring  
make  
```

GUE Configuration
=================
_**agent-port**: GUE tunnel local port. This UDP port will be used as the source port for sending the encapsulated mirrored-traffic._  
_**gue-interface**: GUE tunnel interface name._  
_**collector-eth-ip**: IP address of the collector._  
_**agent-ip**: IP address of the local machine which is running the agent and the TMT ttl: TTL_  
_**collector-port**: GUE tunnel port receiving the traffic on the collector. This UDP port will be used as the destination port for sending the encapsulated mirrored-traffic._  

* **Agent**  
```
modprobe fou  
ip fou add port <agent-port> gue  
ip link add name <gue-interface> type ipip remote <collector-eth-ip> local <agent-ip> ttl <ttl> encap gue encap-sport <agent-port> encap-dport <collector-port>  
ip link set <gue-interface> up  
```

* **Collector**  
```
modprobe fou  
ip fou add port <collector-port> gue  
# Note: Omit ipip remote <agent-ip> from the command below to allow accepting mirrored traffic from multiple sources.   
ip link add name <gue-interface> type ipip remote <agent-ip> local <collector-eth-ip> ttl  <ttl> encap gue encap-sport <collector-port> encap-dport <agent-port>  
ip link set <gue-interaface> up  
```

Usage
=====
* **Ingress Mirroring**  

/usr/src/linux/samples/bpf/eBPF-Package-Repository/traffic-mirroring/l3af_traffic_mirroring/mirroring \\ \
\--iface=\<interface name\> \\  
\--direction=ingress \\  
\--map-name=\<location of the tc-root map for chaining\> \\  
\--src-address=\<list of the source addresses (Use 0.0.0.0 for mirroring packets with "any" src IP)\> \\  
\--tunnel-type=gue \\  
\--tunnel-local-port=\<local tunnel port\> \\  
\--tunnel-remote-port=\<remote tunnel port\> \\  
\--tunnel-remote-address=\<local tunnel IP address\> \\  
\--redirect-to=\<interface name for diverting the mirrored packets\> \\  
\--src-port=\<list of source ports (Use 0 for mirroring packets with "any" src port)\> \\  
\--dst-port=\<list of destination ports (Use 0 for mirroring packets with "any" dst port)\> \\  
\--protocol=\<list of source protocols (udp/tcp/icmp)\>  
\--gtw-address=\<IP address of the gateway\>  


* **Egress Mirroring**

/usr/src/linux/samples/bpf/eBPF-Package-Repository/traffic-mirroring/l3af_traffic_mirroring/mirroring \\ \
\--iface=\<interface name\> \\  
\--direction=egress \\  
\--map-name=\<location of the tc-root map for chaining\> \\  
\--dst-address=\<list of the destination addresses (Use 0.0.0.0 for mirroring packets with "any" dst IP)\> \\  
\--tunnel-type=gue \\  
\--tunnel-local-port=\<local tunnel port\> \\  
\--tunnel-remote-port=\<remote tunnel port\> \\  
\--tunnel-remote-address=\<local tunnel IP address\> \\  
\--redirect-to=\<interface name for diverting the mirrored packets\> \\  
\--src-port=\<list of source ports (Use 0 for mirroring packets with "any" src port)\> \\  
\--dst-port=\<list of destination ports (Use 0 for mirroring packets with "any" dst port)\> \\  
\--protocol=\<list of source protocols (udp/tcp/icmp)\>  
\--gtw-address=\<IP address of the gateway\>  

Note: If the "--gtw-address" option is not provided, the default gateway will be set as x.x.x.1 for the route. Where x.x.x is the same as the first three octets of the local <agent-ip> used for Agent GUE configuration.  


Limitations
=================
* TMT only supports mirroring packets based on the udp/tcp/icmp protocols    
* TMT only supports mirroring IPv4 packets    

