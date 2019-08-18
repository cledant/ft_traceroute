# ft_traceroute

This 42 project aims to implement a IPv4 traceroute binary.

## Compiling

You may compile `ft_traceroute` by running `cmake`.

## Usage

You need to be `root` or use `sudo` in order to use `ft_traceroute`.

Usage: ft_traceroute \[-hnIT\] \[-q nqueries\] \[-f first_ttl\] \[-m max_ttl\] \[-p port\] host \[packet_size\]  
-h : Display usage  
-n : No name lookup for host address  
-I : Use ICMP echo for probes  
-T : Use TCP sync for probes  
-q : Number of probe number per hop. Default is 3. Max is 10  
-f : TTL value at start. Default is 1  
-m : Max TTL value. Default is 30  
-p : Port  
For UDP probe : initial port and is incremented at each probe  
ICMP probe : initial sequence value  
TCP probe : constant port value  
Packet size. From 0 to MTU value minus headers.  
MTU value is usually 1500  