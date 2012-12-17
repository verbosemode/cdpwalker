#!/usr/bin/env python
#
# Version: 0.815
# Author: jochen.bartl@gmail.com
# Dependencies: apt-get install python-pysnmp4 graphviz
#
# WARNING: Crappy code, way to much stuff is hardcoded, ....
#
# Usage:
#         ./cdpwalker.py topology.dot 192.168.0.1
#         dot -Tpdf -o topology.pdf topology.dot
#

from __future__ import with_statement

import sys
import logging
import struct
from pysnmp.entity.rfc3413.oneliner import cmdgen

logger = logging.getLogger("cdpwalker")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

OID_SYSNAME = '1.3.6.1.2.1.1.5.0'
OID_CDP_CACHE_ENTRY = '1.3.6.1.4.1.9.9.23.1.2.1.1'
OID_CDP_CACHE_DEVICEID = '1.3.6.1.4.1.9.9.23.1.2.1.1.6.'
OID_CDP_CACHE_DEVICEPORT = '1.3.6.1.4.1.9.9.23.1.2.1.1.7.'
OID_CDP_CACHE_ADDRESS = '1.3.6.1.4.1.9.9.23.1.2.1.1.4.'


# (host1, host1_if, host2, host2_if)
NEIGHBOR_TABLE = []
DEVICES = {}

class SnmpSession(object):
    """SNMP Session object"""

    def __init__(self):
        self.host = "localhost"
        self.port = 161
        self.community = "public"
        self.version = "2c"

    def get_config(self):
        if self.version == "1":
            return  cmdgen.CommunityData('test-agent', self.community, 0),

        elif self.version == "2c":
            return cmdgen.CommunityData('test-agent', self.community)

        elif self.version == "3":
            return cmdgen.UsmUserData('test-user', 'authkey1', 'privkey1'),

    def oidstr_to_tuple(self, s):
        """ FIXME remove trailing dot if there is one"""

        return tuple([int(n) for n in s.split(".")])

    def snmp_get(self, oid):
        r = ()

        oid = self.oidstr_to_tuple(oid)

        snmp_config = self.get_config()

        errorIndication, errorStatus, \
            errorIndex, varBinds = cmdgen.CommandGenerator().getCmd(
            snmp_config, cmdgen.UdpTransportTarget((self.host, self.port)), oid)

        if errorIndication:
            print errorIndication
            print errorStatus
            print errorIndex
        else:
            if errorStatus:
                print '%s at %s\n' % (
                    errorStatus.prettyPrint(), varBinds[int(errorIndex)-1])
            else:
                for name, val in varBinds:
                    return (name.prettyPrint(), val.prettyPrint())

    def snmp_getnext(self, oid):
        r = []

        oid = self.oidstr_to_tuple(oid)
        snmp_config = self.get_config()

        errorIndication, errorStatus, errorIndex, \
            varBindTable = cmdgen.CommandGenerator().nextCmd(
            snmp_config, cmdgen.UdpTransportTarget((self.host, self.port)), oid)

        if errorIndication:
            print errorIndication
            print errorStatus
            print errorIndex
        else:
            if errorStatus:
                print '%s at %s\n' % (
                    errorStatus.prettyPrint(), varBindTable[-1][int(errorIndex)-1])
            else:
                for varBindTableRow in varBindTable:
                    for name, val in varBindTableRow:
                        r.append((name.prettyPrint(), val.prettyPrint()))

        return r



class CdpDevice(object):
    deviceid = ""
    deviceport = ""
    address = ""


def get_cache_ifindex(snmpoid):
    return int(snmpoid.split(".")[-2])


def get_cdp_neighbors(host):
    neighbors = {}
    neighbor_relations = []
    hostname = ""
    snmpversion = "2c"
    snmpcommunity = "public"

    logger.info("processing host: %s" % host)

    snmp = SnmpSession()
    snmp.host = host
    r = snmp.snmp_getnext(OID_CDP_CACHE_ENTRY)
    if r == []:
        logger.warn("failed to query %s by snmp" % host)
        return [], []

    for e in r:
        snmpoid, value = e[0], e[1]
        ifindex = get_cache_ifindex(snmpoid)

        if not ifindex in neighbors:
            neighbors[ifindex] = CdpDevice()

        if snmpoid.startswith(OID_CDP_CACHE_ADDRESS):
            neighbors[ifindex].address = "%i.%i.%i.%i" % \
                    (struct.unpack("BBBB", value))
        elif snmpoid.startswith(OID_CDP_CACHE_DEVICEID):
            neighbors[ifindex].deviceid = value
        elif snmpoid.startswith(OID_CDP_CACHE_DEVICEPORT):
            if hostname == "":
                hostname = snmp.snmp_get(OID_SYSNAME)[1]
            # ifDescr
            ifname = snmp.snmp_get("1.3.6.1.2.1.2.2.1.2.%i" % ifindex)[1]
            deviceport = value
            var1 = (hostname, ifname, neighbors[ifindex].deviceid, deviceport)
            var2 = (neighbors[ifindex].deviceid, deviceport, hostname, ifname)
            if not var1 in neighbor_relations and not var2 in neighbor_relations:
                neighbor_relations.append(var1)

    return [neighbors[neigh] for neigh in neighbors], neighbor_relations


def print_relations(relations, filename=None):
    # FIXME: Configurable template!!!
    with file(filename, "w") as f:
        f.write("digraph G {\n")
        f.write("rankdir=LR;")
        f.write("size=\"8.5\";")
        f.write("nodesep=\"3.0\";")

        for relation in relations:
            if "Gigabit" in relation[1] and "Gigabit" in relation[3]:
                linkcolor = "green"
            else:
                linkcolor = "blue"

            f.write("\"%s\"->\"%s\" [ label=\"(%s - %s)\",color=%s ];\n" % \
                            (relation[0], relation[2], relation[1], relation[3], linkcolor))

        f.write("}")


def merge_relations(relations, relations2):
    for relation in relations2:
        relation_var2 = (relation[2], relation[3], relation[0], relation[1])
        if not relation in relations and not relation_var2 in relations:
            relations.append(relation)

    return relations


if __name__ == "__main__":
    relations = []
    filename = sys.argv[1]
    hosts = []
    hostsdone = []

    for host in sys.argv[2:]:
        hosts.append(host)

    while hosts != []:
        host = hosts.pop()
        h, rel = get_cdp_neighbors(host)
        relations = merge_relations(relations, rel)
        logger.info("host %s done" % host)
        hostsdone.append(host)

        for host in h:
            if host.address == "127.0.0.1":
                logger.warn("host %s has 127.0.0.1 as it's neighbor?!" % hostsdone[-1])
            elif not host.address in hostsdone:
                logger.info("new host to query %s" % host.address)
                hosts.append(host.address)

    print_relations(relations, filename)

