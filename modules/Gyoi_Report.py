#!/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import copy
import configparser
import pandas as pd

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


# Create report.
class CreateReport:
    def __init__(self, utility):
        self.utility = utility
        # Read config file.
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.report_dir = os.path.join(self.root_path, config['Report']['report_path'])
            self.report_path = os.path.join(self.report_dir, config['Report']['report_name'])
            self.header = str(config['Report']['header']).split('@')
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Create report's header.
    def create_report_header(self, fqdn):
        self.utility.print_message(NOTE, 'Create report header : {}'.format(self.report_path))
        self.utility.write_log(20, '[In] Create report header [{}].'.format(self.file_name))

        self.report_path = self.report_path.replace('*', fqdn)
        pd.DataFrame([], columns=self.header).to_csv(self.report_path, mode='w', index=False)
        self.utility.write_log(20, '[Out] Create report header [{}].'.format(self.file_name))

    # Create report's body.
    def create_report_body(self, url, fqdn, port, cloud, method, products, type, comments, errors, srv_header, log_file, date):
        self.utility.print_message(NOTE, 'Create {}:{} report\'s body.'.format(fqdn, port))
        self.utility.write_log(20, '[In] Create report body [{}].'.format(self.file_name))

        # Build base structure.
        report = []
        login_prob = ''
        login_reason = ''
        if len(type) != 0:
            login_prob = 'Log : ' + type['ml']['prob'] + ' %\n' + 'Url : ' + type['url']['prob'] + ' %'
            login_reason = 'Log : ' + type['ml']['reason'] + '\n' + 'Url : ' + type['url']['reason']
        else:
            login_prob = '*'
            login_reason = '*'
        record = []
        record.insert(0, fqdn)                                # FQDN.
        record.insert(1, self.utility.forward_lookup(fqdn))   # IP address.
        record.insert(2, str(port))      # Port number.
        record.insert(3, cloud)          # Cloud service type.
        record.insert(4, method)         # Using method.
        record.insert(5, url)            # Target URL.
        record.insert(6, '-')            # Vendor name.
        record.insert(7, '-')            # Product name.
        record.insert(8, '-')            # Product version.
        record.insert(9, '-')            # Trigger of identified product.
        record.insert(10, '-')           # Product category.
        record.insert(11, '-')           # CVE number of product.
        record.insert(12, login_prob)    # Login probability.
        record.insert(13, login_reason)  # Trigger of login page.
        record.insert(14, '-')           # Unnecessary comments.
        record.insert(15, '-')           # Unnecessary Error messages.
        record.insert(16, srv_header)    # Server header.
        record.insert(17, log_file)      # Path of log file.
        record.insert(18, date)          # Creating date.
        report.append(record)

        # Build prduct record.
        for product in products:
            product_record = copy.deepcopy(record)
            product_record[6] = product[1]
            product_record[7] = product[2]
            product_record[8] = product[3]
            product_record[9] = product[4]
            product_record[10] = product[0]
            product_record[11] = product[5]
            report.append(product_record)

        # Build comment record.
        for comment in comments:
            comment_record = copy.deepcopy(record)
            comment_record[14] = comment
            report.append(comment_record)

        # Build error message record.
        for error in errors:
            error_record = copy.deepcopy(record)
            error_record[15] = error
            report.append(error_record)

        # Output report.
        msg = 'Create report : {}'.format(self.report_path)
        self.utility.print_message(OK, msg)
        self.utility.write_log(20, msg)
        pd.DataFrame(report).to_csv(self.report_path, mode='a', header=False, index=False)

        self.utility.write_log(20, '[Out] Create report body [{}].'.format(self.file_name))
