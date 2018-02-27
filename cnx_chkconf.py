#!/usr/bin/python
__author__ = 'telekom'

import os
import re
import sys
import logging
import smtplib
import ConfigParser

from config.common_config import *

CONF_FILE = 'chkcfg.ini'
RANCID_DIR = 'rancid'
LOG_FILE_NAME = "chk_cfg.log"
logging.basicConfig(filename=LOG_FILE_NAME, filemode='w', format=u'%(asctime)s  %(message)s', level=logging.INFO)
VRF_NTP = [
'ntp server 10.30.235.210 prefer use-vrf management',
'ntp server 10.30.9.210 prefer use-vrf management',
]
LOCAL_USERS = [
'username admin password 5 $1$axjLk2q3$eZj.8dWWChj3bR0YEemND1  role network-admin',
'username evogaming password 5 $1$FN/4pmVr$.KyzWEyIt21kEr9Kgm5BC.  role network-admin',
]
class chkcfg:
    def __init__(self):
        if not os.path.exists(RANCID_DIR):
            raise IOError('No RANCID directory found: %s' % RANCID_DIR)
            sys.exit()
        self.config = ConfigParser.ConfigParser()
        self.config.read(CONF_FILE) 
        self.ntp = {'private':[self.config.get('Main','ntp1'), self.config.get('Main','ntp2')],'public':[self.config.get('Main','ntp_pub')]}
        self.log = {'rix':self.config.get('Main','log_rix1'), 'mlt':self.config.get('Main','log_mlt1'), 'zzz':self.config.get('Main','log_other')}
        self.report = {}

    def validate_config_file(self, file_path):
        absent_config_lines = []

        with open(file_path, 'r') as file:
            config_lines = file.read().splitlines()
            self.validate_required_lines(absent_config_lines, config_lines, COMMON_CONFIG)

        print(str(absent_config_lines) + '\r\n')

    def validate_required_lines(self, absent_config_lines, config_lines, required_lines):
        for required_line in required_lines:
            if required_line not in config_lines:
                absent_config_lines.append(required_line)
                # logger.info(file + ': Config missing: ' + str(i))

    def validate_syslog_configuration(self, absent_config_lines, config_lines):
        # SYSLOG check
        matching = [config_line for config_line in config_lines if re.match(r'^logging.*\d+\.\d+\.\d+\.\d+', config_line, re.MULTILINE | re.IGNORECASE)]
        if not matching:
            absent_config_lines.append("SYSLOG server not set")
        # if 'rix' in file:
        #     if "logging server " + self.log['rix'] in matching:
        #         matching.remove("logging server " + self.log['rix'])
        #     if "logging server " + self.log['rix'] + " 7 use-vrf management" in matching:
        #         matching.remove("logging server " + self.log['rix'] + " 7 use-vrf management")
        # elif 'mlt1' in file:
        #     if "logging server " + self.log['mlt'] in matching:
        #         matching.remove("logging server " + self.log['mlt'])
        #     if "logging server " + self.log['mlt'] + " 7 use-vrf management" in matching:
        #         matching.remove("logging server " + self.log['mlt'] + " 7 use-vrf management")
        # else:
        #     if "logging server " + self.log['zzz'] in matching:
        #         matching.remove("logging server " + self.log['zzz'])
        #     if "logging server " + self.log['zzz'] + " 7 use-vrf management" in matching:
        #         matching.remove("logging server " + self.log['zzz'] + " 7 use-vrf management")
        # if matching:
        #     for i in matching:
        #         increct.append("SYSLOG: " + str(i))

    def validate_local_users(self, absent_config_lines, config_lines):
        # Local user check
        matching = [config_line for config_line in config_lines if re.match(r'^username .*', config_line, re.MULTILINE | re.IGNORECASE)]
        if matching:
            for i in LOCAL_USERS:
                if i not in matching:
                    absent_config_lines.append(i)
                    # logger.info(file + ': Username not set for:' + str(i))
                else:
                    matching.remove(i)
            # if matching:
            #     for x in matching:
            #         increct.append("Username should not be here: " + str(x))
            #         logger.info(file + ': Username incorrect configured:' + x)
        else:
            absent_config_lines.append("Username not set")
            # logger.info(file + ': Username not set:')

    def validate_ntp_server(self, absent_config_lines, config_lines):
        # NTP check
        matching = [config_line for config_line in config_lines if "ntp server " in config_line]
        if matching:
            for i in VRF_NTP:
                if i not in matching:
                    absent_config_lines.append(i)
                    # logger.info(file + ': NTP cfg server not set:' + str(i))
                else:
                    matching.remove(i)
            # if matching:
            #     for x in matching:
            #         increct.append("NTP: " + str(x))
            #         logger.info(file + ': NTP server incorrect setup:' + x)
        else:
            absent_config_lines.append("NTP server not set")
            # logger.info(file + ': NTP server not set:')

    def validate_port_configuration(self, absent_config_lines, config_lines):
        # Generate port dict
        port_cfg = {}
        for line in config_lines:
            indent = len(line) - len(line.lstrip())
            if indent == 0 and re.match(
                    r'^(line|interface|aaa group server tacacs+|policy-map type network-qos|system|fex) (\S+)', line):
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
                            absent_config_lines.append("interface " + port + "\n       storm-control broadcast level 5.00")
                            # logger.info(file + ': interface ' + port + ' config missing: storm-control broadcast level 5.00')
                        if "storm-control multicast level 5.00" not in port_cfg.get(port):
                            absent_config_lines.append("interface " + port + "\n       storm-control multicast level 5.00")
                            # logger.info(file + ': interface ' + port + ' config missing: storm-control multicast level 5.00')
                    else:
                        if "storm-control broadcast level 5.00" not in port_cfg.get(port):
                            absent_config_lines.append("interface " + port + "\n       storm-control broadcast level 5.00")
                            # logger.info(file + ': interface ' + port + ' config missing: storm-control broadcast level 5.00')
                        if "storm-control multicast level 5.00" not in port_cfg.get(port):
                            absent_config_lines.append("interface " + port + "\n       storm-control multicast level 5.00")
                            # logger.info(file + ': interface ' + port + ' config missing: storm-control multicast level 5.00')
                        if "no snmp trap link-status" not in port_cfg.get(port):
                            absent_config_lines.append("interface " + port + "\n       no snmp trap link-status")
                            # logger.info(file + ': interface ' + port + ' config missing: no snmp trap link-status')
                        if "vpc orphan-port suspend" not in port_cfg.get(port):
                            absent_config_lines.append("interface " + port + "\n       vpc orphan-port suspend")
                            # logger.info(file + ': interface ' + port + ' config missing: vpc orphan-port suspend')
                        if "switchport mode trunk" in port_cfg.get(port):
                            if "spanning-tree port type edge trunk" not in port_cfg.get(port):
                                absent_config_lines.append("interface " + port + "\n       spanning-tree port type edge trunk")
                                # logger.info(file + ': interface ' + port + ' config missing: spanning-tree port type edge trunk')
                        else:
                            if "spanning-tree port type edge" not in port_cfg.get(port):
                                absent_config_lines.append("interface " + port + "\n       spanning-tree port type edge")
                                # logger.info(file + ': interface ' + port + ' config missing: spanning-tree port type edge')
            elif 'port-channel' in port:
                if [z for z in port_cfg.get(port) if re.match(r'.*(-hpc|-ios|-asa|-cnx|-csb|-h3c)', z, re.M | re.I)]:
                    if "storm-control broadcast level 5.00" not in port_cfg.get(port):
                        absent_config_lines.append("interface " + port + "\n       storm-control broadcast level 5.00")
                        # logger.info(file + ': interface ' + port + ' config missing: storm-control broadcast level 5.00')
                    if "storm-control multicast level 5.00" not in port_cfg.get(port):
                        absent_config_lines.append("interface " + port + "\n       storm-control multicast level 5.00")
                        # logger.info(file + ': interface ' + port + ' config missing: storm-control multicast level 5.00')
                else:
                    if "storm-control broadcast level 5.00" not in port_cfg.get(port):
                        absent_config_lines.append("interface " + port + "\n       storm-control broadcast level 5.00")
                        # logger.info(file + ': interface ' + port + ' config missing: storm-control broadcast level 5.00')
                    if "storm-control multicast level 5.00" not in port_cfg.get(port):
                        absent_config_lines.append("interface " + port + "\n       storm-control multicast level 5.00")
                        # logger.info(file + ': interface ' + port + ' config missing: storm-control multicast level 5.00')
                    if "no snmp trap link-status" not in port_cfg.get(port):
                        absent_config_lines.append("interface " + port + "\n       no snmp trap link-status")
                        # logger.info(file + ': interface ' + port + ' config missing: no snmp trap link-status')
                    if "switchport mode trunk" in port_cfg.get(port):
                        if "spanning-tree port type edge trunk" not in port_cfg.get(port):
                            absent_config_lines.append("interface " + port + "\n       spanning-tree port type edge trunk")
                            # logger.info(file + ': interface ' + port + ' config missing: spanning-tree port type edge trunk')
                    else:
                        if "spanning-tree port type edge" not in port_cfg.get(port):
                            absent_config_lines.append("interface " + port + "\n       spanning-tree port type edge")
                            # logger.info(file + ': interface ' + port + ' config missing: spanning-tree port type edge')
            elif 'con' in port:
                if "exec-timeout 15" not in port_cfg.get(port):
                    absent_config_lines.append("line " + port + "\n       exec-timeout 15")
                    # logger.info(file + ': line ' + port + ' config missing: exec-timeout 15')
            elif 'group server tacacs+' in port:
                if "server 10.30.32.4" not in port_cfg.get(port):
                    absent_config_lines.append("aaa " + port + "\n       server 10.30.32.4")
                    # logger.info(file + ': aaa ' + port + ' config missing: TAC+ server ip')
                if "use-vrf management" not in port_cfg.get(port):
                    absent_config_lines.append("aaa " + port + "\n       use-vrf management")
                    # logger.info(file + ': aaa ' + port + ' config missing: use-vrf management')
                if "deadtime 1" not in port_cfg.get(port):
                    absent_config_lines.append("aaa " + port + "\n       deadtime 1")
                    # logger.info(file + ': aaa ' + port + ' config missing: deadtime 1')
            elif 'jumbo' in port:
                if "class type network-qos class-default" not in port_cfg.get(port):
                    absent_config_lines.append("policy-map type network-qos " + port + "\n       class type network-qos class-default")
                    # logger.info(file + ': policy-map type network-qos ' + port + ' config missing: exec-timeout 15')
                if " mtu 9100" not in port_cfg.get(port):
                    absent_config_lines.append("policy-map type network-qos " + port + "\n        mtu 9100")
                    # logger.info(file + ': policy-map type network-qos ' + port + ' config missing:  mtu 9100')
            elif 'qos' in port:
                if "service-policy type network-qos jumbo" not in port_cfg.get(port):
                    absent_config_lines.append("system " + port + "\n       service-policy type network-qos jumbo")
                    # logger.info(file + ': system ' + port + ' config missing: service-policy type network-qos jumbo')
            elif re.match(r"^\d+", port, re.M | re.I):
                if "pinning max-links 1" not in port_cfg.get(port):
                    absent_config_lines.append("fex " + port + "\n       pinning max-links 1")
                    # logger.info(file + ': fex ' + port + ' config missing: pinning max-links 1')

    def run(self):
        for directory in os.listdir(RANCID_DIR):
            backup_dir = RANCID_DIR + "/" + directory + "/configs/"
            if not os.path.exists(backup_dir):
                continue
            for file in os.listdir(backup_dir):
                if re.match(r'^.*-cnx$',file) and not os.stat(backup_dir+file).st_size == 0:
                    self.validate_config_file(backup_dir + file)

                    not_cfg = [] # config should be but absence
                    increct = [] # redundant config
                    with open(backup_dir+file,'r') as f:
                        data = f.read().splitlines()



                    if not_cfg or increct:
                        self.report[file] = (not_cfg, increct)
    
                    logger.info(file + ': finished')


        # if self.report:
        #     email = smtplib.SMTP('localhost')
        #     email_text = ""
        #     for i in self.report:
        #         email_text += '{0}:\n  Not configured lines:\n'.format(i)
        #         for k in self.report[i][0]:
        #             email_text += '    {0}\n'.format(k)
        #         email_text += '{0}:\n  Incorrect settings:\n'.format(i)
        #         for k in self.report[i][1]:
        #             email_text += '    {0}\n'.format(k)
        #         email_text += '\n'
        #
        #     logger.info(email_text)
        #     email.sendmail('cfg_check', 'noc@evolutiongaming.com', 'From: cfg_check\r\nTo: noc@evolutiongaming.com\r\nSubject: Nexus SW configuration check report\r\n\r\n'+email_text)
        #     email.quit()


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logger.info("Test")
    r = chkcfg()
    r.run()
