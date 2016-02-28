import argparse
import os
import sys

import math
from random import randint

from OTXv2 import OTXv2
import IndicatorTypes


class SuricataClient(object):
    ip_rule_template = "alert ip $HOME_NET any -> any any (msg:\"OTX internal host talking to host known in pulse\"; flow:to_server; iprep:dst,Pulse,>,30; sid:41414141; rev:1;)\n"
    ip_category_template = "41,Pulse,OTX community identified IP address\n"
    ip_rep_template = "{ip},41,127\n"

    file_rule_template = "alert http any any -> $HOME_NET any (msg:\"OTX - FILE MD5 from pulse {name}\";  filemd5:{pulse_md5_file}; reference: url, otx.alienvault.com/pulse/{pulse_id}; sid:41{random}; rev:1;)"

    def __init__(self, api_key, base_dir):
        self.client = OTXv2(api_key=api_key, project="Suricata")
        self.base_dir = base_dir

    def get_destination(self, param):
        return open(self.get_path(param), mode='w')

    def get_path(self, param):
        return os.path.join(base_dir, param)

    def generate_rules(self, generate_md5_rules=False, generate_iprep=False):
        with self.get_destination('otx_file_rules.rules') as file_rule_file:
            with self.get_destination('reputation.list') as rep_file:
                md5_file_count = 0
                ip_count = 0
                for pulse in self.client.getall_iter():
                    pulse_id = pulse['id']
                    md5_list = []
                    ip_list = []
                    for indicator in pulse["indicators"]:
                        type_ = indicator["type"]
                        if type_ is IndicatorTypes.FILE_HASH_MD5.name:
                            md5_list.append(indicator["indicator"])
                        if type_ in [IndicatorTypes.IPv4.name, IndicatorTypes.IPv6.name]:
                            ip_list.append(indicator["indicator"])

                    if len(md5_list) > 0 and generate_md5_rules:
                        md5_file = '{0}.txt'.format(pulse_id)
                        self.add_file_rule(file_rule_file, md5_file, pulse, pulse_id)
                        self.write_hash_file(md5_list)
                        md5_file_count += 1
                    if len(ip_list) > 0 and generate_iprep:
                        self.add_iprep(rep_file, ip_list)
                        ip_count += len(ip_list)
                if generate_iprep:
                    self.write_core_iprep_files()
                    sys.stdout.write("Wrote related iprep rules to {}\n".format(file.name))
                    sys.stdout.write("Wrote {0} IPv4 & IPv6 to {1}\n".format(str(ip_count), rep_file.name))
                    sys.stdout.write("========================================\n")
                    sys.stdout.write(
                            "To leverage generated files, enable the suricata iprep feature in suricata.yaml\n")
                    sys.stdout.write(
                            "A default configuration for iprep with these rules can be enabled by appending the following to suricata.yaml\n")
                    sys.stdout.write("========================================\n")
                    sys.stdout.write("NOTE: Please read the docs to adapt for your environment\n")
                    sys.stdout.write("========== Start YAML Snippet ==========\n")
                    sys.stdout.write("reputation-categories-file: {}\n".format(self.get_path('categories.txt')))
                    sys.stdout.write("default-reputation-path: {}\n".format(self.base_dir))
                    sys.stdout.write("reputation-files:\n")
                    sys.stdout.write(" - reputation.list\n")
                    sys.stdout.write("rule-files:\n")
                    sys.stdout.write(" - {}\n".format(self.get_path('otx_iprep.rules')))
                    sys.stdout.write("==========  End YAML Snippet  ==========\n")
                if generate_md5_rules:
                    sys.stdout.write("Wrote {0} md5 hash files to {1}\n".format(str(md5_file_count), self.base_dir))
                    sys.stdout.write("Wrote {0} rules to {1}\n".format(str(md5_file_count), file_rule_file.name))
                    sys.stdout.write("========================================\n")
                    sys.stdout.write("To leverage generated files, enable the suricata file feature in suricata.yaml\n")
                    sys.stdout.write(
                            "A default configuration for the file feature with these rules can be enabled by append the following to suricata.yaml\n")
                    sys.stdout.write(
                        "The following was a snippet from 'http://jasonish-suricata.readthedocs.org/en/latest/file-extraction/file-extraction.html'\n")
                    sys.stdout.write("========================================\n")
                    sys.stdout.write("NOTE: Please read the docs to adapt for your environment\n")
                    sys.stdout.write("========== Start YAML Snippet ==========\n")
                    sys.stdout.write("- file-log:\n")
                    sys.stdout.write("    enabled: yes\n")
                    sys.stdout.write("    filename: files-json.log\n")
                    sys.stdout.write("    append: yes\n")
                    sys.stdout.write("    force-magic: no\n")
                    sys.stdout.write("    force-md5: no\n")
                    sys.stdout.write("    waldo: file.waldo\n")
                    sys.stdout.write("==========  End YAML Snippet  ==========\n")

    def add_file_rule(self, rule_file=None, md5_file=None, pulse=None, pulse_id=None):
        rule_file.write(SuricataClient.file_rule_template.format(name=pulse['name'],
                                                                 pulse_md5_file=md5_file,
                                                                 pulse_id=pulse_id,
                                                                 random=randint(1000, 9999)))

    def write_hash_file(self, md5_list, md5_file=None):
        with self.get_destination(md5_file) as hash_file:
            hash_file.writelines(md5_list)

    def add_iprep(self, rep_file, ip_list):
        rep_file.writelines(ip_list)

    def write_core_iprep_files(self):
        with self.get_destination('categories.txt') as file:
            file.write(SuricataClient.ip_category_template)
        with self.get_destination('otx_iprep.rules') as file:
            file.write(SuricataClient.ip_rule_template)


def getArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-iprep", action='store_true', default=False,
                        help="Do not generate IP Reputation files and rules")
    parser.add_argument("--skip-filemd5", action='store_true', default=False, help="Do not generate file MD5 and rules")
    parser.add_argument("--key", required=True,help="Your OTX API key (https://otx.alienvault.com/api)")
    parser.add_argument("--destination-directory", "-dd", required=False, type=argparse.FileType('w'),
                        help="The destination directory for the generated file")
    return parser.parse_args()


if __name__ == '__main__':
    print sys.argv
    args = getArgs()
    if args.destination_directory:
        base_dir = args.destination_directory
    else:
        base_dir = os.getcwd()
    sclient = SuricataClient(args.key, base_dir)
    sclient.generate_rules(not args.skip_iprep, not args.skip_filemd5)
