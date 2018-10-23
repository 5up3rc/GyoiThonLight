#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import time
import codecs
import urllib3
import configparser
from googleapiclient.discovery import build
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class GoogleCustomSearch:
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
            self.method_name = config['Common']['method_search']
            self.api_key = config['GyoiGoogleHack']['api_key']
            self.search_engine_id = config['GyoiGoogleHack']['search_engine_id']
            self.signature_base = config['GyoiGoogleHack']['signature_base']
            self.api_strict_key = config['GyoiGoogleHack']['api_strict_key']
            self.api_strict_value = config['GyoiGoogleHack']['api_strict_value']
            self.start_index = int(config['GyoiGoogleHack']['start_index'])
            self.delay_time = float(config['GyoiGoogleHack']['delay_time'])
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    def execute_google_hack(self, cve_explorer, fqdn, target, report):
        self.utility.print_message(NOTE, 'Execute Google hack.')
        self.utility.write_log(20, '[In] Execute Google hack [{}].'.format(self.file_name))

        # Open signature file.
        signature_file = os.path.join(self.signature_dir, self.signature_base + target + '.txt')
        with codecs.open(signature_file, 'r', encoding='utf-8') as fin:
            signatures = fin.readlines()

            # Execute Google search.
            for signature in signatures:
                signature = signature.replace('\n', '').replace('\r', '').split('@')
                query = 'site:' + fqdn + ' ' + signature[4]
                result_count = self.custom_search(query, self.start_index)

                if result_count != 0:
                    # Found search result.
                    msg = 'Detected {} : {}/{}'.format(target, signature[1], signature[2])
                    self.utility.print_message(OK, msg)
                    self.utility.write_log(20, msg)
                    product_list = [signature[0], signature[1], signature[2], signature[3], query]
                    product_list = cve_explorer.cve_explorer([product_list])
                    report.create_report_body('-', fqdn, '*', '*', self.method_name,
                                              product_list, {}, [], [], '*', '*', self.utility.get_current_date())

                time.sleep(self.delay_time)
        self.utility.write_log(20, '[Out] Execute Google custom search [{}].'.format(self.file_name))

    # APIのアクセスはIPで制限
    # 制限の設定はGCP consoleで実施。
    def custom_search(self, query, start_index=1):
        # Google Custom Search API.
        self.utility.write_log(20, '[In] Execute Google custom search [{}].'.format(self.file_name))

        # Setting of Google Custom Search.
        service = build("customsearch", "v1", developerKey=self.api_key)
        response = []
        result_count = 0

        # Execute search.
        try:
            response.append(service.cse().list(
                q=query,
                cx=self.search_engine_id,
                num=10,
                start=self.start_index
            ).execute())

            msg = 'Execute query: {}'.format(response[0].get('queries').get('request')[0].get('searchTerms'))
            result_count = int(response[0].get('searchInformation').get('totalResults'))
            self.utility.print_message(OK, msg)
            self.utility.write_log(20, msg)
        except Exception as e:
            msg = 'Google custom search is failure : {}'.format(e)
            self.utility.print_exception(e, msg)
            self.utility.write_log(30, msg)
            self.utility.write_log(20, '[Out] Execute Google custom search [{}].'.format(self.file_name))
            return result_count

        self.utility.write_log(20, '[Out] Execute Google custom search [{}].'.format(self.file_name))
        return result_count
