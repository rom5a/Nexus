#!/usr/bin/python
import logging
import re
import ConfigParser
from config.common_config import *


CHASSIS_TYPE_MARKER = "!Chassis type:"
HARDWARE_MARKER = "!Hardware:"
INTERFACE_ETHERNET_MARKER = "interface Ethernet"
INTERFACE_PORT_CHANNEL_MARKER = "interface port-channel"
CONSOLE_MARKER = "line console"
TACACS_MARKER = "aaa group server tacacs+"
JUMBO_POLICY_MAP_MARKER = "policy-map type network-qos jumbo"
SYSTEM_QOS_MARKER = "system qos"
FEX_MARKER = "fex"

class DeviceValidator:

    def __init__(self, file_name, directory):
        self.logger = logging.getLogger(__name__)
        self.config = ConfigParser.ConfigParser()
        self.file_name = file_name
        self.directory = directory
        self.location = file_name.split('-')[0]
        self.absent_config_lines = []
        self.redundant_config_lines = []

        self.device_name = None
        self.device_model = None
        self.model_series = None
        self.ethernet_ports = dict()
        self.channel_ports = dict()
        self.fex = dict()
        self.console_config = []
        self.tacacs_config = []
        self.jumbo_config = []
        self.qos_config = []

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

            elif re.match(r'^' + INTERFACE_ETHERNET_MARKER, config_line, re.IGNORECASE):
                self.logger.debug("Detected ethernet port")
                current_line += self.parse_port_configuration(current_line, self.ethernet_ports)

            elif re.match(r'^' + INTERFACE_PORT_CHANNEL_MARKER, config_line, re.IGNORECASE):
                self.logger.debug("Detected port channel")
                current_line += self.parse_port_configuration(current_line, self.channel_ports)

            elif re.match(r'^' + CONSOLE_MARKER, config_line, re.IGNORECASE):
                self.logger.debug("Detected console configuration")
                current_line += self.common_config_parser(current_line, self.console_config)

            elif re.match(r'^' + TACACS_MARKER, config_line, re.IGNORECASE):
                self.logger.debug("Detected tacacs configuration")
                current_line += self.common_config_parser(current_line, self.tacacs_config)

            elif re.match(r'^' + JUMBO_POLICY_MAP_MARKER, config_line, re.IGNORECASE):
                self.logger.debug("Detected jumbo configuration")
                current_line += self.common_config_parser(current_line, self.jumbo_config)

            elif re.match(r'^' + SYSTEM_QOS_MARKER, config_line, re.IGNORECASE):
                self.logger.debug("Detected qos configuration")
                current_line += self.common_config_parser(current_line, self.qos_config)

            elif re.match(r'^' + FEX_MARKER, config_line, re.IGNORECASE):
                self.logger.debug("Detected fex configuration")
                current_line += self.parse_port_configuration(current_line, self.fex)

            else:
                current_line += 1

        self.logger.debug("Finish parsing configuration file")

        self.logger.debug("Read location specific config")
        self.model_series = re.search(r'\d', self.device_model).group()
        if not self.config.read('config_template/' + self.location + '-' + self.model_series + '-config.ini'):
            self.logger.error("Failed read config")
            raise ValueError("Failed read config")
        self.logger.debug("Reading finished")

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

    def parse_port_configuration(self, line_number, port_container):
        self.logger.debug("Parsing port configuration at line(" + str(line_number) + ")")
        parsed_lines = 0
        config_line = self.config_lines[line_number]
        port_name = config_line.split(" ")[1]
        port_parsed = False
        while not port_parsed:
            parsed_lines += 1
            config_line = self.config_lines[line_number + parsed_lines]
            config_line_length = len(config_line.lstrip())
            if port_name not in port_container:
                port_container[port_name] = []

            if config_line_length > 0:
                port_container[port_name].append(config_line.lstrip())

            port_parsed = config_line_length == 0 or config_line[0] != ' ' or (line_number + parsed_lines >= len(self.config_lines))

        return parsed_lines

    def common_config_parser(self, line_number, array_container):
        self.logger.debug("Parsing configuration")
        parsed_lines = 1
        console_config_parsed = False

        while not console_config_parsed:
            config_line = self.config_lines[line_number + parsed_lines]

            if len(config_line) == 0 or config_line[0] != ' ' or line_number + parsed_lines >= len(self.config_lines):
                console_config_parsed = True
            else:
                array_container.append(config_line.lstrip())

            parsed_lines += 1

        return parsed_lines

    def validate(self):
        self.logger.info("Validation result for " + str(self.file_name))
        self.validate_mandatory_lines()
        self.validate_syslog_configuration()
        self.validate_local_users()
        self.validate_ntp_server()
        self.validate_ethernet()
        self.validate_channel_ports()
        self.validate_console_configuration()
        self.validate_tacacs_configuration()
        self.validate_jumbo_configuration()
        self.validate_qos_configuration()
        self.validate_fex()

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

        server_configs = eval(self.config.get("Main", "log_server_config"))
        for server_config in server_configs:
            if server_config not in matching:
                self.logger.info("\t\t" + server_config)
                self.absent_config_lines.append(server_config)

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

    def validate_ethernet(self):
        self.logger.info("\tEthernet config validation:")
        ethernet_configs = eval(self.config.get('Main', 'ethernet_config'))
        description_pattern = re.compile('^description.*')
        channel_group_pattern = re.compile("^channel-group.*")
        ip_address_pattern = re.compile("^ip address.*")

        for ethernet_port in self.ethernet_ports:
            log_result = []
            port_configs = self.ethernet_ports[ethernet_port]

            if (self.model_series == "5" and "shutdown" in port_configs) or len(port_configs) == 0 or \
                    filter(ip_address_pattern.match, port_configs):
                continue

            log_result.append('\t\t' + ethernet_port)

            for common_config in ethernet_configs:
                if common_config not in port_configs:
                    log_result.append('\t\t\t' + common_config)
                    self.absent_config_lines.append(common_config)

            if not filter(description_pattern.match, port_configs):
                log_result.append('\t\t\tdescription')
                self.absent_config_lines.append('description')

            if not filter(channel_group_pattern.match, port_configs) and "vpc orphan-port suspend" not in port_configs:
                log_result.append('\t\t\tvpc orphan-port suspend')
                self.absent_config_lines.append('vpc orphan-port suspend')

            for port_config in port_configs:
                if re.match(r'^switchport access', port_config, re.IGNORECASE) and 'spanning-tree port type edge' not in port_configs:
                    self.logger.info('\t\t\tspanning-tree port type edge')
                    self.absent_config_lines.append('spanning-tree port type edge')

                elif 'switchport mode trunk' is port_config and 'spanning-tree port type edge trunk' not in port_configs:
                    log_result.append('\t\t\tspanning-tree port type edge trunk')
                    self.absent_config_lines.append('spanning-tree port type edge trunk')

            if len(log_result) > 1:
                for log_line in log_result:
                    self.logger.info(log_line)

        self.logger.info("")

    def validate_channel_ports(self):
        self.logger.info("\tChannel ports config validation:")
        ethernet_configs = eval(self.config.get('Main', 'ethernet_config'))
        description_pattern = re.compile('^description.*')

        for channel_port in self.channel_ports:
            log_result = []
            port_configs = self.channel_ports[channel_port]
            if "shutdown" in port_configs:
                continue

            log_result.append('\t\t' + channel_port)

            for common_config in ethernet_configs:
                if common_config not in port_configs:
                    log_result.append('\t\t\t' + common_config)
                    self.absent_config_lines.append(common_config)

            if not filter(description_pattern.match, port_configs):
                log_result.append('\t\t\tdescription')
                self.absent_config_lines.append('description')

            for port_config in port_configs:
                if re.match(r'^switchport access', port_config, re.IGNORECASE) and 'spanning-tree port type edge' not in port_configs:
                    log_result.append('\t\t\tspanning-tree port type edge')
                    self.absent_config_lines.append('spanning-tree port type edge')
                elif 'switchport mode trunk' is port_config and 'spanning-tree port type edge trunk' not in port_configs:
                    log_result.append('\t\t\tspanning-tree port type edge trunk')
                    self.absent_config_lines.append('spanning-tree port type edge trunk')

            if len(log_result) > 1:
                for log_line in log_result:
                    self.logger.info(log_line)

        self.logger.info("")

    def validate_console_configuration(self):
        self.logger.info("\tConsole config validation:")
        for console_config in CONSOLE_CONFIG:
            if console_config in self.console_config:
                self.logger.info("\t\t" + console_config)
                self.absent_config_lines.append(console_config)
        self.logger.info("")

    def validate_tacacs_configuration(self):
        self.logger.info("\tTacacs config validation:")
        for group_config in GROUP_SERVICE_CONFIG:
            if group_config not in self.tacacs_config:
                self.logger.info("\t\t" + group_config)
                self.absent_config_lines.append(group_config)
        self.logger.info("")

    def validate_jumbo_configuration(self):
        self.logger.info("\tJumbo config validation:")
        for jumbo_config in JUMBO_CONFIG:
            if jumbo_config not in self.jumbo_config:
                self.logger.info("\t\t" + jumbo_config)
                self.absent_config_lines.append(jumbo_config)
        self.logger.info("")

    def validate_qos_configuration(self):
        self.logger.info("\tQOS config validation:")
        for qos_config in QOS_CONFIG:
            if qos_config not in self.qos_config:
                self.logger.info("\t\t" + qos_config)
                self.absent_config_lines.append(qos_config)
        self.logger.info("")

    def validate_fex(self):
        self.logger.info("\tFex config validation:")
        description_pattern = re.compile('^description.*')

        for fex_port in self.fex:
            log_result = []
            port_configs = self.fex[fex_port]
            if "shutdown" in port_configs:
                continue

            log_result.append('\t\t' + fex_port)

            for common_config in FEX_CONFIG:
                if common_config not in port_configs:
                    log_result.append('\t\t\t' + common_config)
                    self.absent_config_lines.append(common_config)

            if not filter(description_pattern.match, port_configs):
                log_result.append('\t\t\tdescription')
                self.absent_config_lines.append('description')

            if len(log_result) > 1:
                for log_line in log_result:
                    self.logger.info(log_line)

        self.logger.info("")
