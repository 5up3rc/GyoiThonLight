#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import codecs
import time
import configparser
import urllib3
from urllib3 import util
from util import Utilty
from modules.Gyoi_CloudChecker import CloudChecker
from modules.Gyoi_VersionChecker import VersionChecker
from modules.Gyoi_CommentChecker import CommentChecker
from modules.Gyoi_ErrorChecker import ErrorChecker
from modules.Gyoi_Report import CreateReport
from modules.Gyoi_PageTypeChecker import PageChecker
from modules.Gyoi_GoogleHack import GoogleCustomSearch
from modules.Gyoi_ContentExplorer import ContentExplorer
from modules.Gyoi_SpiderControl import SpiderControl
from modules.Gyoi_CveExplorerNVD import CveExplorerNVD
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


# Get target information.
def get_target_info(full_path, utility):
    utility.write_log(20, '[In] Get target information [{}].'.format(os.path.basename(__file__)))
    protocol = []
    fqdn = []
    port = []
    path = []
    try:
        with codecs.open(os.path.join(full_path, 'host.txt'), 'r', 'utf-8') as fin:
            targets = fin.readlines()
            for target in targets:
                items = target.replace('\r', '').replace('\n', '').split(' ')
                if len(items) != 4:
                    utility.print_message(FAIL, 'Invalid target record : {}'.format(target))
                    utility.write_log(30, 'Invalid target record : {}'.format(target))
                    continue
                protocol.append(items[0])
                fqdn.append(items[1])
                port.append(items[2])
                path.append(items[3])
    except Exception as e:
        utility.print_message(FAIL, 'Invalid file: {}'.format(e))
        utility.write_log(30, 'Invalid file: {}'.format(e))

    utility.write_log(20, '[Out] Get target information [{}].'.format(os.path.basename(__file__)))
    return protocol, fqdn, port, path


# Display banner.
def show_banner(utility):
    banner = """
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 ██████╗██╗   ██╗ ██████╗ ██╗████████╗██╗  ██╗ ██████╗ ███╗   ██╗
██╔════╝╚██╗ ██╔╝██╔═══██╗██║╚══██╔══╝██║  ██║██╔═══██╗████╗  ██║
██║  ███╗╚████╔╝ ██║   ██║██║   ██║   ███████║██║   ██║██╔██╗ ██║
██║   ██║ ╚██╔╝  ██║   ██║██║   ██║   ██╔══██║██║   ██║██║╚██╗██║
╚██████╔╝  ██║   ╚██████╔╝██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
 ╚═════╝   ╚═╝    ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  (beta)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
""" + 'by ' + os.path.basename(__file__)
    utility.print_message(NONE, banner)
    show_credit(utility)
    time.sleep(utility.banner_delay)


# Show credit.
def show_credit(utility):
    credit = u"""
       =[ GyoiThon v0.0.1-beta                               ]=
+ -- --=[ Author  : Gyoiler (@gyoithon)                      ]=--
+ -- --=[ Website : https://github.com/gyoisamurai/GyoiThon/ ]=--
    """
    utility.print_message(NONE, credit)


# main.
if __name__ == '__main__':
    file_name = os.path.basename(__file__)
    full_path = os.path.dirname(os.path.abspath(__file__))

    utility = Utilty()
    utility.write_log(20, '[In] GyoiThon [{}].'.format(file_name))

    # Read config.ini.
    config = configparser.ConfigParser()
    config.read(os.path.join(full_path, 'config.ini'))

    # Common setting value.
    log_path = ''
    method_crawl = ''
    try:
        log_dir = config['Common']['log_path']
        log_path = os.path.join(full_path, log_dir)
        method_crawl = config['Common']['method_crawl']
    except Exception as e:
        msg = 'Reading config.ini is failure : {}'.format(e)
        utility.print_exception(e, msg)
        utility.write_log(40, msg)
        utility.write_log(20, '[Out] GyoiThon [{}].'.format(file_name))
        exit(1)

    # Show banner.
    show_banner(utility)

    # Create instances.
    cloud_checker = CloudChecker(utility)
    version_checker = VersionChecker(utility)
    comment_checker = CommentChecker(utility)
    error_checker = ErrorChecker(utility)
    page_checker = PageChecker(utility)
    google_hack = GoogleCustomSearch(utility)
    content_explorer = ContentExplorer(utility)
    spider = SpiderControl(utility)
    report = CreateReport(utility)
    cve_explorer = CveExplorerNVD(utility)

    # Get target information from "host.txt".
    protocol_list, fqdn_list, port_list, path_list = get_target_info(full_path, utility)

    # Start investigation.
    for idx in range(len(fqdn_list)):
        # Check parameters.
        msg = 'investigation : {}, {}, {}, {}'.format(protocol_list[idx], fqdn_list[idx], port_list[idx], path_list[idx])
        utility.write_log(20, 'Start ' + msg)
        if utility.check_arg_value(protocol_list[idx], fqdn_list[idx], port_list[idx], path_list[idx]) is False:
            msg = 'Invalid parameter : {}, {}, {}, {}'.format(protocol_list[idx], fqdn_list[idx],
                                                              port_list[idx], path_list[idx])
            utility.print_message(FAIL, msg)
            utility.write_log(30, msg)
            continue

        # Create report header.
        report.create_report_header(fqdn_list[idx])

        # Check cloud service.
        cloud_type = cloud_checker.get_cloud_service(fqdn_list[idx])

        # Gather target url using Spider.
        web_target_info = spider.run_spider(protocol_list[idx], fqdn_list[idx], port_list[idx], path_list[idx])

        # Get HTTP responses.
        for target in web_target_info:
            for count, target_url in enumerate(target[2]):
                utility.print_message(NOTE, '{}/{} Start analyzing: {}'.format(count+1, len(target[2]), target_url))

                # Check target url.
                parsed = None
                try:
                    parsed = util.parse_url(target_url)
                except Exception as e:
                    utility.print_exception(e, 'Parsed error : {}'.format(target_url))
                    utility.write_log(30, 'Parsed error : {}'.format(target_url))
                    continue

                # Get HTTP response (header + body).
                date = utility.get_current_date('%Y%m%d%H%M%S%f')[:-3]
                print_date = utility.transform_date_string(utility.transform_date_object(date[:-3], '%Y%m%d%H%M%S'))
                _, server_header, res_header, res_body = utility.send_request('GET', target_url)

                # Write log.
                log_name = protocol_list[idx] + '_' + fqdn_list[idx] + '_' + str(port_list[idx]) + '_' + date + '.log'
                log_file = os.path.join(log_path, log_name)
                with codecs.open(log_file, 'w', 'utf-8') as fout:
                    fout.write(res_header + res_body)

                # Check product name/version.
                product_list = version_checker.get_product_name(res_header + res_body)

                # Get CVE for products.
                product_list = cve_explorer.cve_explorer(product_list)

                # Check unnecessary comments.
                comments = comment_checker.get_bad_comment(res_body)

                # Check unnecessary error messages.
                errors = error_checker.get_error_message(res_body)

                # Check login page.
                page_type = page_checker.judge_page_type(target_url, res_body)

                # Create report.
                report.create_report_body(target_url,
                                          fqdn_list[idx],
                                          port_list[idx],
                                          cloud_type,
                                          method_crawl,
                                          product_list,
                                          page_type,
                                          comments,
                                          errors,
                                          server_header,
                                          log_file,
                                          print_date)

        # Check CMS using Google Hack and Explore contents.
        #google_hack.execute_google_hack(cve_explorer, fqdn_list[idx], 'cms', report)
        content_explorer.content_explorer(cve_explorer, protocol_list[idx], fqdn_list[idx], port_list[idx], path_list[idx], 'cms', report)

        # Check unnecessary contents using Google Hack and Explore contents.
        #google_hack.execute_google_hack(cve_explorer, fqdn_list[idx], 'unfile', report)
        content_explorer.content_explorer(cve_explorer, protocol_list[idx], fqdn_list[idx], port_list[idx], path_list[idx], 'unfile', report)

        utility.write_log(20, 'End ' + msg)

    print(os.path.basename(__file__) + ' finish!!')
    utility.write_log(20, '[Out] GyoiThon [{}].'.format(file_name))
