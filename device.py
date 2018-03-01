#!/usr/bin/python
import logging
import re
from config.common_config import *

CHASSIS_TYPE_MARKER = "!Chassis type:"
HARDWARE_MARKER = "!Hardware:"
INTERFACE_ETHERNET_MARKER = "interface Ethernet"

class DeviceValidator:

    def __init__(self, file_name, directory):
        self.logger = logging.getLogger(__name__)
        self.file_name = file_name
        self.directory = directory
        self.location = file_name.split('-')[0]
        self.absent_config_lines = []
        self.redundant_config_lines = []

        self.device_name = None
        self.device_model = None
        self.ethernet_ports = []

        self.logger.debug("Creating device validator for location(" + str(self.location) + ")")

        self.logger.debug("Reading file(" + str(file_name) + ") in directory(" + str(directory) + ")")
        with open(directory + file_name, 'r') as f:
            self.config_lines = f.read().splitlines()
        self.parse_config_file()

    def parse_config_file(self):
        self.logger.debug("Start parsing configuration file")

        current_line =0
        while current_line < len(self.config_lines):
            config_line = self.config_lines[current_line]

            if not self.device_name and CHASSIS_TYPE_MARKER in config_line:
                self.logger.debug("Detected chassis type")
                current_line += self.parse_hardware_info(current_line)

            if re.match(r'^' + INTERFACE_ETHERNET_MARKER, config_line, re.IGNORECASE):
                self.logger.debug("Detected ethernet port")
                current_line += self.parse_ethernet_configuration(current_line)

            current_line += 1

        self.logger.debug("Finish parsing configuration file")

    def parse_hardware_info(self, line_number):
        self.logger.debug("Searching device name and model")
        parsed_lines = 0
        hardware_info_found = False
        while not hardware_info_found:
            config_line = self.config_lines[line_number + parsed_lines]

            if HARDWARE_MARKER in config_line and re.match(r'.*cisco.*', config_line, re.IGNORECASE):
                hardware_info = config_line.split(" ")
                self.device_name = hardware_info[2]
                self.device_model = hardware_info[3]

            parsed_lines += 1
            hardware_info_found = (self.device_name is not None) or (line_number + parsed_lines >= len(self.config_lines))

        self.logger.debug("Finish searching device name and model")
        return parsed_lines

    def parse_ethernet_configuration(self, line_number):
        parsed_lines = 1
        config_line = self.config_lines[line_number]
        port_name = config_line.split(" ")[1]
        ethernet_port_parsed = False
        while not ethernet_port_parsed:
            config_line = self.config_lines[line_number + parsed_lines]
            # TODO finish port parsing
            parsed_lines += 1
            ethernet_port_parsed = len(config_line) == 0 or (line_number + parsed_lines >= len(self.config_lines))


        return parsed_lines

    def validate(self):
        self.logger.info("Validation result for " + str(self.file_name))
        self.validate_mandatory_lines()
        self.validate_syslog_configuration()
        self.validate_local_users()
        self.validate_ntp_server()
        self.validate_port_configuration()

    def validate_mandatory_lines(self):
        self.logger.info("\tMandatory config lines missed: ")
        for required_line in COMMON_CONFIG:
            if required_line not in self.config_lines:
                self.absent_config_lines.append(required_line)
                self.logger.info("\t\t" + str(required_line))

        self.logger.info("")

    def validate_syslog_configuration(self):
        self.logger.info("\tSYSLOG configuration: ")
        matching = [config_line for config_line in self.config_lines
                    if re.match(r'^logging.*\d+\.\d+\.\d+\.\d+', config_line, re.MULTILINE | re.IGNORECASE)]

        if not matching:
            self.absent_config_lines.append("SYSLOG server not set")
            self.logger.info("\t\tSYSLOG server not set")

        # if 'rix' in self.location:
        #     if "logging server " + self.log['rix'] in matching:
        #         matching.remove("logging server " + self.log['rix'])
        #     if "logging server " + self.log['rix'] + " 7 use-vrf management" in matching:
        #         matching.remove("logging server " + self.log['rix'] + " 7 use-vrf management")
        #
        # elif 'mlt1' in self.location:
        #     if "logging server " + self.log['mlt'] in matching:
        #         matching.remove("logging server " + self.log['mlt'])
        #     if "logging server " + self.log['mlt'] + " 7 use-vrf management" in matching:
        #         matching.remove("logging server " + self.log['mlt'] + " 7 use-vrf management")
        #
        # else:
        #     if "logging server " + self.log['zzz'] in matching:
        #         matching.remove("logging server " + self.log['zzz'])
        #     if "logging server " + self.log['zzz'] + " 7 use-vrf management" in matching:
        #         matching.remove("logging server " + self.log['zzz'] + " 7 use-vrf management")

        if matching:
            self.logger.info("\tRedundant SYSLOG config")
            for redundant_line in matching:
                self.redundant_config_lines.append("SYSLOG: " + str(redundant_line))
                self.logger.info("\t\t" + str(redundant_line))

        self.logger.info("")

    def validate_local_users(self):
        self.logger.info("\tUsers validation:")
        matching = [config_line for config_line in self.config_lines
                    if re.match(r'^username .*', config_line, re.MULTILINE | re.IGNORECASE)]
        if matching:
            self.logger.info("\tUser missing:")
            for local_user in LOCAL_USERS:
                if local_user not in matching:
                    self.absent_config_lines.append(local_user)
                    self.logger.info("\t\t" + str(local_user))
                else:
                    matching.remove(local_user)

            if matching:
                self.logger.info("")
                self.logger.info("\tRedundant users:")
                for user in matching:
                    self.redundant_config_lines.append("Username should not be here: " + str(user))
                    self.logger.info("\t\t" + str(user))
        else:
            self.absent_config_lines.append("Users not set")
            self.logger.info("\t\tUsers not set")

        self.logger.info("")

    def validate_ntp_server(self):
        self.logger.info("\tNTP config validation:")
        matching = [config_line for config_line in self.config_lines if "ntp server " in config_line]
        if matching:
            self.logger.info("\tNTP server config missing:")
            for ntp_server in VRF_NTP:
                if ntp_server not in matching:
                    self.absent_config_lines.append(ntp_server)
                    self.logger.info("\t\t" + str(ntp_server))
                else:
                    matching.remove(ntp_server)

            if matching:
                self.logger.info("\tNTP server redundant config:")
                for ntp_config_line in matching:
                    self.redundant_config_lines.append("NTP: " + str(ntp_config_line))
                    self.logger.info("\t\t" + str(ntp_config_line))
        else:
            self.absent_config_lines.append("NTP server not set")
            self.logger.info("\t\tNTP server not set")

        self.logger.info("")

    def validate_port_configuration(self):
        self.logger.info("\tPort config validation:")
        port_cfg = {}
        for line in self.config_lines:
            indent = len(line) - len(line.lstrip())
            if indent == 0 and re.match(r'^(line|interface|aaa group server tacacs+|policy-map type network-qos|system|fex) (\S+)', line):
                port = " ".join(line.split()[1:])
                port_cfg[port] = []
            elif indent == 0:
                port = None
            elif port and indent > 0:
                port_cfg[port].append(line.lstrip())

                # Check port configuration
        for port in port_cfg:
            if [z for z in port_cfg.get(port) if re.match(r'^shutdown$', z, re.M | re.I)]:
                continue
            if 'Ethernet' in port:
                if not [z for z in port_cfg.get(port) if re.match(r'^channel-group.*', z, re.M | re.I)]:
                    if [z for z in port_cfg.get(port) if
                        re.match(r'.*(-hpc|-ios|-asa|-cnx|-csb|-h3c)', z, re.M | re.I)]:
                        if "storm-control broadcast level 5.00" not in port_cfg.get(port):
                            self.absent_config_lines.append("interface " + port + "\n       storm-control broadcast level 5.00")
                            self.logger.info('\t\tinterface ' + port + ' config missing: storm-control broadcast level 5.00')
                        if "storm-control multicast level 5.00" not in port_cfg.get(port):
                            self.absent_config_lines.append("interface " + port + "\n       storm-control multicast level 5.00")
                            self.logger.info('\t\tinterface ' + port + ' config missing: storm-control multicast level 5.00')
                    else:
                        if "storm-control broadcast level 5.00" not in port_cfg.get(port):
                            self.absent_config_lines.append("interface " + port + "\n       storm-control broadcast level 5.00")
                            self.logger.info('\t\tinterface ' + port + ' config missing: storm-control broadcast level 5.00')
                        if "storm-control multicast level 5.00" not in port_cfg.get(port):
                            self.absent_config_lines.append("interface " + port + "\n       storm-control multicast level 5.00")
                            self.logger.info('\t\tinterface ' + port + ' config missing: storm-control multicast level 5.00')
                        if "no snmp trap link-status" not in port_cfg.get(port):
                            self.absent_config_lines.append("interface " + port + "\n       no snmp trap link-status")
                            self.logger.info('\t\tinterface ' + port + ' config missing: no snmp trap link-status')
                        if "vpc orphan-port suspend" not in port_cfg.get(port):
                            self.absent_config_lines.append("interface " + port + "\n       vpc orphan-port suspend")
                            self.logger.info('\t\tinterface ' + port + ' config missing: vpc orphan-port suspend')
                        if "switchport mode trunk" in port_cfg.get(port):
                            if "spanning-tree port type edge trunk" not in port_cfg.get(port):
                                self.absent_config_lines.append("interface " + port + "\n       spanning-tree port type edge trunk")
                                self.logger.info('\t\tinterface ' + port + ' config missing: spanning-tree port type edge trunk')
                        else:
                            if "spanning-tree port type edge" not in port_cfg.get(port):
                                self.absent_config_lines.append("interface " + port + "\n       spanning-tree port type edge")
                                self.logger.info('\t\tinterface ' + port + ' config missing: spanning-tree port type edge')
            elif 'port-channel' in port:
                if [z for z in port_cfg.get(port) if re.match(r'.*(-hpc|-ios|-asa|-cnx|-csb|-h3c)', z, re.M | re.I)]:
                    if "storm-control broadcast level 5.00" not in port_cfg.get(port):
                        self.absent_config_lines.append("interface " + port + "\n       storm-control broadcast level 5.00")
                        self.logger.info('\t\tinterface ' + port + ' config missing: storm-control broadcast level 5.00')
                    if "storm-control multicast level 5.00" not in port_cfg.get(port):
                        self.absent_config_lines.append("interface " + port + "\n       storm-control multicast level 5.00")
                        self.logger.info('\t\tinterface ' + port + ' config missing: storm-control multicast level 5.00')
                else:
                    if "storm-control broadcast level 5.00" not in port_cfg.get(port):
                        self.absent_config_lines.append("interface " + port + "\n       storm-control broadcast level 5.00")
                        self.logger.info('\t\tinterface ' + port + ' config missing: storm-control broadcast level 5.00')
                    if "storm-control multicast level 5.00" not in port_cfg.get(port):
                        self.absent_config_lines.append("interface " + port + "\n       storm-control multicast level 5.00")
                        self.logger.info('\t\tinterface ' + port + ' config missing: storm-control multicast level 5.00')
                    if "no snmp trap link-status" not in port_cfg.get(port):
                        self.absent_config_lines.append("interface " + port + "\n       no snmp trap link-status")
                        self.logger.info('\t\tinterface ' + port + ' config missing: no snmp trap link-status')
                    if "switchport mode trunk" in port_cfg.get(port):
                        if "spanning-tree port type edge trunk" not in port_cfg.get(port):
                            self.absent_config_lines.append("interface " + port + "\n       spanning-tree port type edge trunk")
                            self.logger.info('\t\tinterface ' + port + ' config missing: spanning-tree port type edge trunk')
                    else:
                        if "spanning-tree port type edge" not in port_cfg.get(port):
                            self.absent_config_lines.append("interface " + port + "\n       spanning-tree port type edge")
                            self.logger.info('\t\tinterface ' + port + ' config missing: spanning-tree port type edge')
            elif 'con' in port:
                if "exec-timeout 15" not in port_cfg.get(port):
                    self.absent_config_lines.append("line " + port + "\n       exec-timeout 15")
                    self.logger.info('\t\tline ' + port + ' config missing: exec-timeout 15')
            elif 'group server tacacs+' in port:
                if "server 10.30.32.4" not in port_cfg.get(port):
                    self.absent_config_lines.append("aaa " + port + "\n       server 10.30.32.4")
                    self.logger.info('\t\taaa ' + port + ' config missing: TAC+ server ip')
                if "use-vrf management" not in port_cfg.get(port):
                    self.absent_config_lines.append("aaa " + port + "\n       use-vrf management")
                    self.logger.info('\t\taaa ' + port + ' config missing: use-vrf management')
                if "deadtime 1" not in port_cfg.get(port):
                    self.absent_config_lines.append("aaa " + port + "\n       deadtime 1")
                    self.logger.info('\t\taaa ' + port + ' config missing: deadtime 1')
            elif 'jumbo' in port:
                if "class type network-qos class-default" not in port_cfg.get(port):
                    self.absent_config_lines.append("policy-map type network-qos " + port + "\n       class type network-qos class-default")
                    self.logger.info('\t\tpolicy-map type network-qos ' + port + ' config missing: exec-timeout 15')
                if " mtu 9100" not in port_cfg.get(port):
                    self.absent_config_lines.append("policy-map type network-qos " + port + "\n        mtu 9100")
                    self.logger.info('\t\tpolicy-map type network-qos ' + port + ' config missing:  mtu 9100')
            elif 'qos' in port:
                if "service-policy type network-qos jumbo" not in port_cfg.get(port):
                    self.absent_config_lines.append("system " + port + "\n       service-policy type network-qos jumbo")
                    self.logger.info('\t\tsystem ' + port + ' config missing: service-policy type network-qos jumbo')
            elif re.match(r"^\d+", port, re.M | re.I):
                if "pinning max-links 1" not in port_cfg.get(port):
                    self.absent_config_lines.append("fex " + port + "\n       pinning max-links 1")
                    self.logger.info('\t\tfex ' + port + ' config missing: pinning max-links 1')
