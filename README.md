# FloWrita

This is a program designed to infer a network topology based on sFlow
information received. sflowtool is used as a listener and sFlow receiver. Input
is collected from stdin, and the appropriate usage is

        "sflowtool | ./discoverer.py"

This is tested with mininet network emulation software
(https://github.com/mininet/mininet) but is designed to work as an sflow
collector that parses RFC3176 compliant sflow traffic from any type of network
device.
