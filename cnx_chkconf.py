#!/usr/bin/python
__author__ = 'telekom'

import os
import re
import sys
import logging
import smtplib
import ConfigParser

from config.common_config import *
from device import *

CONF_FILE = 'chkcfg.ini'
RANCID_DIR = 'rancid'
LOG_FILE_NAME = "chk_cfg.log"
logging.basicConfig(filename=LOG_FILE_NAME, filemode='w', format=u'%(asctime)s  %(message)s', level=logging.INFO)

class chkcfg:
    def __init__(self):
        if not os.path.exists(RANCID_DIR):
            raise IOError('No RANCID directory found: %s' % RANCID_DIR)
            sys.exit()

    def run(self):
        for directory in os.listdir(RANCID_DIR):
            backup_dir = RANCID_DIR + "/" + directory + "/configs/"
            if not os.path.exists(backup_dir):
                continue
            for file in os.listdir(backup_dir):
                if re.match(r'^.*-cnx$',file) and not os.stat(backup_dir+file).st_size == 0:
                    try:
                        device_validator = DeviceValidator(file, backup_dir)
                        device_validator.validate()

                    except Exception as e:
                        logger.error(file + " ignored " + str(e))

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
    logger.setLevel(logging.DEBUG)
    r = chkcfg()
    r.run()
