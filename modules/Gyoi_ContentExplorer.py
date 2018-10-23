#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import codecs
import time
import urllib3
import configparser
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class ContentExplorer:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.signature_dir = os.path.join(self.root_path, config['Common']['signature_path'])
            self.method_name = config['Common']['method_direct']
            self.signature_base = config['ContentExplorer']['signature_base']
            self.delay_time = float(config['ContentExplorer']['delay_time'])
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Explore unnecessary contents.
    def content_explorer(self, cve_explorer, protocol, fqdn, port, path, target_category, report):
        self.utility.print_message(NOTE, 'Explore unnecessary contents.')
        self.utility.write_log(20, '[In] Explore contents [{}].'.format(self.file_name))

        # Open signature file.
        target_base = protocol + '://' + fqdn + ':' + str(port) + path
        signature_file = os.path.join(self.signature_dir, self.signature_base + target_category + '.txt')
        with codecs.open(signature_file, 'r', encoding='utf-8') as fin:
            signatures = fin.readlines()

            # Explore content.
            for signature in signatures:
                signature = signature.replace('\n', '').replace('\r', '').split('@')
                target_url = ''
                if signature[4].startswith('/') is True:
                    target_url = target_base + signature[4][1:]
                else:
                    target_url = target_base + signature[4]

                # Get HTTP response (header + body).
                date = self.utility.get_current_date('%Y%m%d%H%M%S%f')[:-3]
                print_date = self.utility.transform_date_string(self.utility.transform_date_object(date[:-3], '%Y%m%d%H%M%S'))
                res, server_header, res_header, res_body = self.utility.send_request('GET', target_url)

                # Write log.
                log_name = protocol + '_' + fqdn + '_' + str(port) + '_' + date + '.log'
                log_file = os.path.join(os.path.join(self.root_path, 'logs'), log_name)
                with codecs.open(log_file, 'w', 'utf-8') as fout:
                    fout.write(res_header + res_body)

                if res.status in [200, 301, 302]:
                    # Found unnecessary content or CMS admin page.
                    product_list = [signature[0], signature[1], signature[2], signature[3], signature[4]]
                    product_list = cve_explorer.cve_explorer([product_list])
                    report.create_report_body(target_url, fqdn, port, '*', self.method_name, product_list, {}, [], [],
                                              server_header, log_file, print_date)
                    msg = 'Find product={}/{}, verson={}, trigger={}'.format(signature[1],
                                                                             signature[2],
                                                                             signature[3],
                                                                             signature[4])
                    self.utility.print_message(OK, msg)
                    self.utility.write_log(20, msg)
                time.sleep(self.delay_time)
        self.utility.write_log(20, '[Out] Explore contents [{}].'.format(self.file_name))
