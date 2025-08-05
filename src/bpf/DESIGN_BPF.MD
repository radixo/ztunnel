# Proposal
After creating the `TRANSPARENT_NETWORK_POLICIES` config, that makes ztunnel to proxy the connections through the original destination port instead of the 15008, this design aims to make the port divert on the destination pod to be done via eBPF program(s).

## The Challenge
To divert the package that arrives on the destination, on a arbitrary port (like 80), but diverts it to the 15008 when is coming from other node that is part of the mesh.
- The package needs to be diverted after passing the external veth pair of the pod.

## The Design
Using a SK_LOOKUP eBPF program, it is possible to bpf_sk_assign to a socket stored on an eBPF socket map.
This type of program is attached to netns, what means that we can attach this program only to the netns that are part of the mesh.
We will need:
* A SOCKHASH map to store the workload IP as the key, and the listening socket on port 15008 created by ztunnel.
* A HASH map containing all the ips that are part of the mesh.

The flow is like:
1. ZTunnel starts:
   - BPF program is loaded
   - eBPF component registers to get messages from Istiod (workloads information)
     On Add / Delete workload, update the HASH map with the mesh IPs.
   - eBPF component registers to get messages from CNI (netns and HBONE listening socket)
     On Add / Delete netns and the socket is created, the loaded program is attached / detached from the netns, and updated the entry on the SOCKHASH map with the IP as the key and sock fd as the value.
2. When the eBPF program will bind the packet to a socket:
   - If the packet is TCP (this version only IPv4 was implemented)
   - And src and dst IPs are part of the mesh
   - And we find the socket registered on the MAP
     **The packet is diverted**

# Results
It was possible to validate that the packet can be diverted and complete the connection succesfully, but one obstacle is still on the way:
1. The connection to the local service needs to happen without being diverted (without being sent back to ZTunnel)
   On the context of the eBPF program there is no way to identify this packet, that contains a kernel mark, but not readable by this type of program.
   **Possible solutions:**
   - Create an other eBPF program of type CGROUP_SKB, that can identify the mark on the packet and append
     it to a new map for the SK_LOOKUP program to skip this divert. It will be needed to bring a cgroup mount point and more permission to the ZTunnel containers.