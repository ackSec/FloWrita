# FloWrita

This is a program designed to infer a network topology based on sFlow
information received. sflowtool is used as a listener and sFlow receiver. Input
is collected from stdin, and the appropriate usage is

        "sflowtool | ./discoverer.py"

This is tested with mininet network emulation software
(http://github.com/mininet) but is designed to work as an sflow collector that
parses RFCXXXX compliant sflow traffic.
