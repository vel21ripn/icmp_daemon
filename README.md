# icmp_daemon
ICMP ping-daemon and services for nagios

The daemon accepts requests to check availability hosts.
Request parameters: host address (ipv4 or ipv6),
checking interval (seconds) and the maximum testing time (seconds).
The first query returns results about first answer from the host and
complete statistics about answers from host for all these queries.
During the time between requests collected statistics on the minimum,
average, and maximum response time, the number of the transmitted and
received packets, the number of state changes.
The number of test hosts is not limited.

The client is fully compatible by options with check_icmp from nagios_plugins.

For daemon server, you can restrict the list of addresses from which requests are allowed.
