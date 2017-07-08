#!/usr/bin/env python3
# coding: utf-8

"""
sflowtool parser for topology discovery
Analyzes incoming sFlow packets and builds similar Mininet topology.


Usage:   sflowtool | ./discoverer.py
   (also see --help)

"""

import sys
import argparse
from collections import deque
from os.path import basename

DEBUG = False

PORT_IGNORE_LIST = ('multiple ', 'dropCode')
MAC_IGNORE_LIST = ('ffffffffffff', )


def log_debug(s):
    """ TODO: use logging module instead """
    if DEBUG:
        sys.stderr.write('{0}\n'.format(s))


def log_info(s):
    """ TODO: use logging module instead """
    sys.stderr.write('\n{0}\n'.format(s))
    sys.stderr.flush()


def warning(s):
    """ TODO: use logging module instead """
    sys.stderr.write('\n\r WARNING! {0}\n\n'.format(s))
    sys.stderr.flush()


def get_host_name(host_ip, fallback):
    """
    Try to infer switch name from switch_id

    >>> get_host_name('10.0.0.12', '012345abcdef')
    'h12'

    >>> get_host_name('192.168.1.1', '012345abcdef')
    'h-192.168.1.1'

    >>> get_host_name(None, '012345abcdef')
    'h-012345abcdef'
    """
    if not host_ip:
        return 'h-' + fallback
    if host_ip.startswith('10.0.0'):
        return 'h' + str(host_ip[host_ip.rindex('.') + 1:])
    else:
        return 'h-' + host_ip


def get_switch_name(swname):
    """
    Try to infer switch name from switch_id

    >>> get_switch_name('2:1012')
    'sw-13'

    >>> get_switch_name('2:1a')
    'sw-1a'

    >>> get_switch_name('abcd')
    'sw-abcd'
    """
    if swname.startswith('2:1'):
        possible_num = swname[swname.index(':') + 1:]
        try:
            possible_num = int(possible_num)
            if 1000 <= possible_num < 2000:
                possible_num -= 1000 - 1
            possible_num = str(possible_num)
        except ValueError:
            pass
        return 'sw-' + possible_num
    return 'sw-' + swname


def make_python_var(name):
    """ Return node name, suitable for python identifier """
    return name.replace('-', '').replace('.', '_')


class Sample(dict):
    """
    Class to represent one sample inside sFlow datagram
    """
    def __init__(self, *arg, **kw):
        super(Sample, self).__init__(*arg, **kw)


class Datagram(object):
    """
    Class contains one sFlow datagram
    """
    def __init__(self, lines=None):
        """ Build Datagram object """
        self.params = {}
        self.samples = []
        if lines:
            self.parse_lines(lines)

    def parse_lines(self, lines):
        """
        Populates object fields with data
        """
        try:
            assert lines[0].startswith('startDatagram')
            assert lines[-1].startswith('endDatagram')
        except AssertionError:
            warning('datagram assertion failed')
            sys.stderr.write('\n'.join((str(x) for x in lines)))
            sys.stderr.flush()
        samples = []
        sample = None
        for line in lines[1:-1]:
            token, value = line.rstrip().split(' ', 1)
            assert token == line.split()[0]
            if sample:  # inside sample lines
                if token == 'endSample':
                    samples.append(Sample(sample))
                    sample = None
                else:
                    sample[token] = value
            elif token == 'startSample':
                sample = {'start': 0}
            else:
                self.params[token] = value
        if sample:
            warning('abnormal sample termination :-) inside datagram')
        self.samples += samples     # all samples inside datagram object

    def __repr__(self):
        return '<Datagram[{0} samples]> = {1}'.format(len(self.samples), self.params)


class Link(object):
    """
    Class represent full path between hosts
    """
    def __init__(self, host1, host2, switch=None):
        if host1 < host2:
            host1, host2 = host2, host1
        self.host1 = host1
        self.host2 = host2
        if switch:
            self.path = set([switch])
        else:
            self.path = set([])

    def __repr__(self):
        """ Return human-readable view of Link object """
        return "<<<Link({0}, {1})={2}>>>".format(self.host1, self.host2, self.path)

    def add(self, switch):
        """ Add switch somewhere in path - not ordered """
        self.path.add(switch)

    def get_pair(self):
        """ Return tuple of two hosts """
        return self.host1, self.host2


class Links(object):
    """ All we know about links between hosts/switches """
    def __init__(self):
        self.links = {}

    def add_switch(self, host1, host2, switch):
        """ add new or extend existing Link """
        if host1 < host2:
            host1, host2 = host2, host1
        try:
            self.links[(host1, host2)].add(switch)
        except KeyError:
            self.links[(host1, host2)] = Link(host1, host2, switch)

    def __repr__(self):
        return 'Links object ({0} paths)'.format(len(self.links))

    def __len__(self):
        return len(self.links)

    def __iter__(self):
        """ Allow to use object as iterator over links """
        for link in self.links.values():
            yield link


class NetworkElement(object):
    """
    Abstract class for network elements
    """
    def __repr__(self):
        """ Every subclass must redefine this """
        raise Exception('Cannot represent abstract class')


class Host(NetworkElement):
    """
    All we know about hosts
    """
    def __init__(self, ip):
        """ Constructor """
        self.ip = ip

    def __repr__(self):
        return '<Host({0}) class object>'.format(self.ip)


class Switch(NetworkElement):
    """
    All we know about switches
    """
    def __init__(self, switch_id):
        """ Constructor """
        self.switch_id = switch_id
        self.ports = {}
        self.datagrams = []

    def __repr__(self):
        """ Trying to show all relevant info about Switch object """
        ports = ', '.join('{0}:[{1}]'.format(x, len(self.ports[x])) for x in self.ports)
        return '<Switch({0}), ports {1}>'.format(self.switch_id, ports)

    def add_dgram(self, datagram):
        """ TODO: shold filter or process datagrams in-place """
        self.datagrams.append(datagram)

    def map_port(self, port, mac):
        """ path to this MAC lies via that port """
        try:
            self.ports[port].add(mac)
        except KeyError:
            self.ports[port] = set([mac])

    def process_ports(self):
        """ Determine hosts <-> ports mapping """
        for dgram in self.datagrams:
            port = dgram['outputPort']
            mac = dgram['dstMAC']
            if not port.startswith(PORT_IGNORE_LIST) and not mac in MAC_IGNORE_LIST:
                self.map_port(port, mac)
            port = dgram['inputPort']
            mac = dgram['srcMAC']
            if not port.startswith(PORT_IGNORE_LIST) and not mac in MAC_IGNORE_LIST:
                self.map_port(port, mac)


class UndirectedGraph(object):
    """
    This class is used to check link inferring - does the path exist in built topology?

    Really abstract, not related with other parts of the program.
    """

    def __init__(self, edges):
        """
        Create graph, infer nodes from edges automatically

        edges is list of pairs/tuples
        """
        self.vertices = {}
        for host1, host2 in edges:
            try:
                self.vertices[host1].add(host2)
            except KeyError:
                self.vertices[host1] = set([host2])      # ignore multiple edges
            try:
                self.vertices[host2].add(host1)
            except KeyError:
                self.vertices[host2] = set([host1])

    def is_path_exist(self, start, finish):
        """ Return bool, uses Breadth-First Search """
        path = set([])
        q = deque()
        q.append(start)
        while len(q):
            tmp = q.popleft()
            if tmp not in path:
                path.add(tmp)
            if tmp == finish:
                return True
            for neighbor in self.vertices[tmp]:
                if neighbor not in path:
                    q.append(neighbor)
        return False


class DerivedTopology(object):
    """
    Here we build network topology from incoming data
    """
    def __init__(self):
        self.switches = {}
        self.hosts = {}
        self.links = Links()
        self.derived_links = set([])
        self.names = {}

    def add_host(self, host_id, ip=None):
        """A host has IP and id==MAC"""
        try:
            host = self.hosts[host_id]
            if ip:
                self.names[host_id] = get_host_name(ip, host_id)
        except KeyError:  # only if host does not exist
            host = Host(ip)
            self.hosts[host_id] = host
            self.names[host_id] = get_host_name(ip, host_id)

    def add_dgram_to_switch(self, sw_id, datagram):
        """A switch has a list of datagrams emitted by it"""
        try:
            self.switches[sw_id].add_dgram(datagram)
        except KeyError:
            self.switches[sw_id] = Switch(sw_id)
            self.switches[sw_id].add_dgram(datagram)

    def map_switch_ports(self):
        """ Determine hosts <-> ports mapping """
        for switch in self.switches.values():
            switch.process_ports()

    def simplify_names(self):
        """ Try to make switch/hosts names more readable """
        for swname in self.switches:
            self.names[swname] = get_switch_name(swname)

    def try_to_simplify(self):
        """
        try to determine switch->leaf links

        leaf can be host or switch, result goes to self.derived_links list
        """
        log_debug('start iteration')
        sure_links = []
        merged_hosts = {}
        # Stage1: merge hosts into directly-connected switches
        for swname, switch in self.switches.items():
            #log_debug('for {0} switch:'.format(swname))
            if len(switch.ports) < 2:
                continue
            switch.direct_hosts = []
            free_ports = []
            for port, hosts in switch.ports.items():
                if len(hosts) == 1:
                    host = hosts.pop()
                    # must sort nodes to make link unique
                    sure_links.append(tuple(sorted((swname, host))))
                    merged_hosts[host] = swname
                    switch.direct_hosts.append(host)
                    free_ports.append(port)
            #log_debug('Switch {0}: freed ports {1}, merged hosts {2}'.format(swname,
            #             free_ports, switch.direct_hosts))
            for port in free_ports:
                switch.ports.pop(port)
        # Stage2: replace merged hosts with switches
        for swname, switch in self.switches.items():
            for port, hosts in switch.ports.items():
                for merged_host, merging_switch in merged_hosts.items():
                    if merged_host in hosts:
                        hosts.remove(merged_host)
                        hosts.add(merging_switch)
                        log_debug('Replacing host {0} with {1} for port {2} of switch {3}'.format(
                            merged_host, merging_switch, port, swname))
        log_debug(self.switches)
        self.derived_links |= set(sure_links)
        log_debug('{0} leafs merged'.format(len(sure_links)))
        return bool(sure_links)

    def simplify_links(self):
        """ iteratively try to simplify graph """
        while self.try_to_simplify():
            pass
        log_debug('no more leaf merging possibilities')
        if not self.is_graph_complete_for_paths():
            log_debug('graph is not connected, adding remaining links between switches...')
            pairs = set([])
            for swname, switch in self.switches.items():
                log_debug('for {0} switch:'.format(swname))
                for neighbors in switch.ports.values():
                    if len(neighbors) == 1:
                        pair = tuple(sorted((swname, list(neighbors)[0])))
                        pairs.add(pair)
            self.derived_links |= pairs

    def generate_graphviz_graph(self):
        """ Return list of strings - graph representation in DOT format """
        result = ['graph G {']
        for node, name in self.names.items():
            if name.startswith('h'):
                result.append('  "{0}" [label="{1}", shape=rectangle]'.format(node, name))
            else:
                result.append('  "{0}" [label="{1}"]'.format(node, name))
        for link in self.derived_links:
            result.append('   "{0}" -- "{1}"'.format(link[0], link[1]))
        result.append('}')
        return result

    def generate_mininet_script(self):
        """ Return list of strings - Python script to recreate topology """

        result = ["""
from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI

net = Mininet(controller=Controller)
c0 = net.addController('c0')
"""]
        for host in self.hosts:
            name = make_python_var(self.names[host])
            result.append("{0} = net.addHost('{0}')\n".format(name))
        for sw in self.switches:
            name = make_python_var(self.names[sw])
            result.append("{0} = net.addSwitch('{0}')\n".format(name))
        for node1, node2 in self.derived_links:
            name1 = make_python_var(self.names[node1])
            name2 = make_python_var(self.names[node2])
            result.append('net.addLink({0}, {1})\n'.format(name1, name2))
        result.append("""
net.start()
CLI(net)
net.stop()
""")
        return result

    def reachable_via_derived(self, link):
        """ Return bool - whether the path between hosts exists in derived_links graph"""
        host1, host2 = link.get_pair()
        nodes = link.path | set([host1, host2])     # all hosts and switches in path
        log_debug(nodes)
        found_links = set([])
        for pair in self.derived_links:
            if pair[0] in nodes and pair[1] in nodes:
                found_links.add(pair)
        log_debug(found_links)
        if len(found_links) == len(nodes) - 1:
            return True
        else:
            log_debug('Direct path between nodes is incomplete, using BFS')
            return self.graph.is_path_exist(host1, host2)

    def is_graph_complete_for_paths(self):
        """
        Return bool - whether all the collected paths between hosts can be travelled
        with current state of derived_links list

        Return bool
        """
        self.graph = UndirectedGraph(self.derived_links)
        log_debug('Checking graph for completeness, links are {0}'.format(self.derived_links))
        return all((self.reachable_via_derived(link) for link in self.links))


def process_datagrams(datagrams):
    """
    Return topology object
    """
    log_info('Processing collected sflow datagrams')
    topo = DerivedTopology()
    for datagram in datagrams:
        for sample in datagram.samples:
            if sample['sampleType'] != 'COUNTERSSAMPLE' \
                and sample['dstMAC'] not in MAC_IGNORE_LIST:
                switch_id = sample['sourceId']
                src_host_mac = sample['srcMAC']
                dst_host_mac = sample['dstMAC']
                topo.add_host(src_host_mac, sample.get('srcIP'))
                topo.add_host(dst_host_mac, sample.get('dstIP'))
                topo.links.add_switch(src_host_mac, dst_host_mac, switch_id)
                topo.add_dgram_to_switch(switch_id, sample)
    log_info("{0} switches".format(len(topo.switches)))
    log_info("{0} hosts".format(len(topo.hosts)))
    log_info("{0} inter-host paths".format(len(topo.links)))
    return topo


def collect_datagrams(args):
    """
    Simple stdin reading until Ctrl-C pressed
    """
    collected = []
    lines = []
    count = 0

    if not args.inputfile or args.inputfile == '-':
        log_info('Collecting sFlows from <<stdin>>, press Ctrl-C to interrupt')
        dgram_input = sys.stdin
        if sys.stdin.isatty():
            warning('Stdin is a tty, you should use "sflowtool | ./{0}" to collect sFlows'.format(
                basename(sys.argv[0])))
    else:
        dgram_input = open(args.inputfile, 'rt')
        log_info('Collecting sFlows from input file {0}...'.format(args.inputfile))
    try:
        while True:
            line = dgram_input.readline().rstrip()
            if not line:                            # EOF reached
                collected.append(Datagram(lines))
                lines = []
                break
            count += 1
            sys.stderr.write('\rStdin lines = {0}, collected datagrams = {1}'.format(count, len(collected)))
            if line.startswith('startDatagram'):
                if lines:
                    warning('garbage before startDatagram')
                lines = [line]
                continue
            lines.append(line)
            if line.startswith('endDatagram'):
                collected.append(Datagram(lines))
                lines = []
    except (KeyboardInterrupt, IOError):
        if lines:
            warning('incomplete last datagram, dropping')
    return collected


def get_commandline_options():
    """
    Return namespace with CLI parameters
    """
    global DEBUG
    parser = argparse.ArgumentParser(description="""SFlow data collector and parser,
        works together with "sflowtool" (https://github.com/sflow/sflowtool)""")
    parser.add_argument('-i', '--inputfile', help="input file in sflowtool format, may be '-' for stdin pipe from sflowtool")
    parser.add_argument('-g', '--graph', help="generate network topology map as Graphviz .dot file")
    parser.add_argument('-m', '--mininet', help="generate Python script to create Mininet topology")
    #parser.add_argument('-j', '--json', help="generate OpenFlow data in JSON format to upload")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="output verbose debugging messages to stderr")
    args = parser.parse_args()
    if args.debug:
        DEBUG = True
    if args.mininet:
        if not args.mininet.endswith('.py'):
            args.mininet += '.py'
    return args


def main():
    """
    Collect datagrams, create topology
    """
    args = get_commandline_options()
    collected = collect_datagrams(args)
    mytopo = process_datagrams(collected)
    mytopo.map_switch_ports()
    for _, switch in mytopo.switches.items():
        log_debug(switch)
    mytopo.simplify_links()
    mytopo.simplify_names()
    if args.graph:
        log_info('Generating network map as Graphiz .dot file {0} ...'.format(args.graph))
        with open(args.graph, 'wt') as output:
            dotlines = mytopo.generate_graphviz_graph()
            output.writelines(dotlines)
        log_info(""" File {0} written successfully, use Graphviz binary to create PNG image
                 e.g. "neato -Tpng -o {0}.png {0}" """.format(args.graph))
    if args.mininet:
        log_info('Generating script for Mininet topology, writing {0} ...'.format(args.mininet))
        with open(args.mininet, 'wt') as outfile:
            script = mytopo.generate_mininet_script()
            if script:
                outfile.writelines(script)
                log_info('Mininet script {0} written successfully'.format(args.mininet))
            else:
                warning('Cannot generate Mininet script, skipping')


if __name__ == "__main__":
    main()
