#icmp_daemon

ICMP ping-daemon and services for nagios \(for linux \)

The daemon accepts requests to check availability hosts.
Request parameters: host address (ipv4 or ipv6),
checking interval (seconds) and the maximum testing time (seconds).
The first query returns results about first answer from the host and
complete statistics about answers from host for all these queries.
During the time between requests collected statistics on the minimum,
average, and maximum response time, the number of the transmitted and
received packets, the number of state changes.
The number of tested hosts is not limited.

The client is fully compatible by options with check\_icmp from nagios\_plugins.

For daemon server, you can restrict the list of addresses from which requests are allowed.

#Build and Install
    make  
    make install

ping\_server install to /usr/local/bin as ping\_server  
ping\_client install to /usr/libexec as check\_icmp\_daemon

#System require

sysctl -w net.ipv4.ping\_group\_range="X X"  
sysctl -w net.ipv6.ping\_group\_range="X X"

X is numeric group-ID (see "nagios\_group=" in nagios.cfg)

#nagios service

Example to replace the standard host command "check-host-alive".

    define command {
      command_name check_icmps
      # ping interval 5 sec, max. testing time 250 sec
      command_line    /usr/libexec/check_icmp_daemon -b 16 -i 5 -T 250 -w 150,20 -c 1000,60 -H $HOSTADDRESS
    }
    define host {
        host_name host
        check_command check_icmps
        ....
    }
