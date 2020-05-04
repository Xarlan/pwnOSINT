#!/usr/bin/env python3

import datetime
import os
import xml.etree.ElementTree as ET
import urllib.request
import urllib.error
import ssl
import socket
import http.client as http_client
import threading
import time
import ipaddress
import queue
import concurrent.futures


import click
import shodan
from nslookup import Nslookup
import sslyze
import sslyze.errors


OUTPUT_DIR = 'output'

# black.
# blue.
# green.
# yellow.
# cyan.
# white.
# magenta.
# red.


DNS_TO_ASK = {
                "google"    : "8.8.8.8",
                "opendns"   : "208.67.222.222",
                "comodo"    : "8.26.56.26",
                "level3"    : "209.244.0.3",
                "advantage" : "156.154.70.1",
                # "opennic"   : "46.151.208.154",
                "dyn"       : "216.146.35.35",
                "safedns"   : "195.46.39.39",
                "watch"     : "84.200.69.80"
                }


class Osint(object):

    def __init__(self):
        if not os.path.isdir(OUTPUT_DIR):
            click.secho("Directory ", nl=False)
            click.secho("output ", nl=False, fg='green')
            click.secho("will be created")
            os.makedirs('output')
        else:
            click.secho("See the result in directory ")

        self.output_dir = os.path.join(os.getcwd(), OUTPUT_DIR)
        click.secho(self.output_dir, fg='green')

        self.fout = ""
        self.msg_queue = queue.Queue()


    def check_fout_name(self, raw_name):
        current_time = datetime.datetime.now()

        raw_name = os.path.split(raw_name)[-1]

        raw_name = current_time.strftime("%Y_%m_%d") + "_" + raw_name

        exists = os.path.isfile(os.path.join(self.output_dir, raw_name))

        if exists:
            self.fout = raw_name + "_" + current_time.strftime("%H_%M")
        else:
            self.fout = raw_name

        self.fout = os.path.join(self.output_dir, self.fout)

        return self.fout


    @staticmethod
    def ipv4_sorted(raw_data):
        """
        Sort list of ipv4 address by ascending
        :param raw_data:    list of ip address
        :return:            sorted list of ipv4 address
        """

        if isinstance(raw_data, list):
            raw_ip = []
            ipv4_hosts = []

            for item in raw_data:
                try:
                    ipaddress.ip_address(item.split('\n')[0])

                except ValueError:
                    click.secho("It seems this is not an ipv4 address: ", nl=False)
                    click.secho("{}".format(item), fg="yellow")

                else:
                    raw_ip.append(item.split('\n')[0])



            for ipv4 in sorted(raw_ip, key=lambda ipv4: (int(ipv4.split(".")[0], 10),
                                                          int(ipv4.split(".")[1], 10),
                                                          int(ipv4.split(".")[2], 10),
                                                          int(ipv4.split(".")[3], 10))):
                ipv4_hosts.append(ipv4)

            return ipv4_hosts

        else:
            click.secho("This is not list of ipv4 address", fg="yellow")
            exit(1)


    def dns2ip_osint(self, fin, fout, humanr):
        """
        Find ipv4 address for list of domain
        :param humanr:      human readable presentation in file
        :param fin:         input file, contain the name of domain
        :param fout:        output file, store the result
        :return:
        """
        fid = open(fin.name, "r")
        list_domains = fid.readlines()
        fid.close()

        dns2ip = {}
        dns2ip_human = {}

        if fout is None:
            fout = fin.name

        self.check_fout_name(fout)

        fid_dns2ip = open(self.fout, "w")

        with click.progressbar(list_domains, label="Completed") as dns_names:

            for domain in dns_names:

                domain = domain.split('\n')[0]
                click.secho("\nFind ip address for: ", nl=False)
                click.secho("{}".format(domain), fg="green")


                for dns_server in DNS_TO_ASK.keys():

                    click.secho("Ask following DNS ", nl=False)
                    click.secho("{:<10} : {}".format(dns_server, DNS_TO_ASK[dns_server]), fg="cyan")

                    dns_query = Nslookup(dns_servers=[DNS_TO_ASK[dns_server]])

                    ips_record = dns_query.dns_lookup(domain)

                    for ip in ips_record.answer:

                        if not (ip in dns2ip):
                            dns2ip.update({ip: domain})
                            fid_dns2ip.write("dns-name:{:<35} => ip:{}\n".format(domain, ip))

                            if domain in dns2ip_human:
                                dns2ip_human[domain].append(ip)
                            else:
                                dns2ip_human.update({domain: [ip]})


        fid_dns2ip.close()
        click.secho("\nResult stored:")
        click.secho(self.fout, fg="green")


        if humanr:

            fid_human = open(self.fout + "_human", "w")

            for domain_name in dns2ip_human.keys():
                click.secho("dns-name:{} =>".format(domain_name))
                fid_human.write("dns-name:{} =>\n".format(domain_name))

                for ip in dns2ip_human[domain_name]:
                    click.secho("{:<38} ip:{}".format(" ", ip))
                    fid_human.write("{:<38} ip:{}\n".format(" ", ip))

            fid_human.close()

            click.secho("\nResult human readable format stored:")
            click.secho(self.fout + "_human", fg="green")


    @staticmethod
    def _dirb_thread(url_base, fout_th):
        click.secho("\n************************************")
        click.secho("* Run web application auditing for ")
        click.secho("* ", nl=False)
        click.secho("http://{}".format(url_base), fg='green')
        click.secho("************************************")

        cmd_dirb = "dirb http://{} -o {}".format(url_base, fout_th)

        os.system(cmd_dirb)


    def mdirb_osint(self, weburls, th):
        """
        Run 'dirb' tools for few web-url simultaneously
        :param weburls:     list of url to check
        :param th:          max number of thread for simultaneously use
        :return:
        """

        fin = open(weburls.name, 'r')
        url_to_check = sorted(fin.readlines())
        fin.close()

        t_dirb = []

        with click.progressbar(url_to_check, label="Completed") as urls:

            for host in urls:

                out_dirb = host.split('\n')[0]
                out_dirb = out_dirb.replace('.', '_')

                fout = self.check_fout_name(out_dirb)

                url_base = host.split('\n')[0]

                if len(t_dirb) < th:

                    t = threading.Thread(target=self._dirb_thread, args=(url_base, fout), name=url_base)
                    t.start()
                    t_dirb.append(t)

                else:
                    wait_finish_th = True

                    while wait_finish_th:

                        for index, dirb_thread in enumerate(t_dirb):

                            if not dirb_thread.is_alive():
                                wait_finish_th = False
                                t_dirb.pop(index)
                                break

                    t = threading.Thread(target=self._dirb_thread, args=(url_base, fout))
                    t_dirb.append(t)

                    t.start()


    def xml2txt(self, xml, fout, tout, humanr):
        """
        Convert to human-readable format xml file from 'masscan' tool
        :param xml:         xml file
        :param fout:        name of output file
        :param tout:        format of output: sort by ip-address or port
        :return:
        """

        try:
            masscan_tree = ET.parse(xml.name)

        except ET.ParseError:
            click.secho("Wrong format of xml", fg='yellow')
            exit(0)

        else:
            root_masscan = masscan_tree.getroot()
            if root_masscan.attrib['scanner'] != 'masscan':
                click.secho("This xml isn't output of masscan tool", fg='yellow')
                exit(0)

                                # dictionary, where will be stored result
            output_ip = {}      # sorted by IP:port
            output_port = {}    # sorted by tcp/udp_port: ip

            for tag_host in root_masscan:

                if len(tag_host.findall(".//")) == 4:

                    ip_addr = ""
                    port = ""
                    tcp_udp = ""

                    for item in tag_host.findall(".//"):

                        if item.tag == 'address':
                            ip_addr = item.attrib['addr']

                        elif item.tag == 'port':
                            port = item.attrib['portid']
                            tcp_udp = item.attrib['protocol']

                    if ip_addr in output_ip:
                        output_ip[ip_addr].append("{}/{}".format(tcp_udp, port))
                    else:
                        output_ip.update({ip_addr: ["{}/{}".format(tcp_udp, port)]})

                    key_port = "{}/{}".format(tcp_udp, port)

                    if key_port in output_port:
                        output_port[key_port].append(ip_addr)
                    else:
                        output_port.update({key_port: [ip_addr]})

            if fout is None:
                fout = xml.name.split('.')[0]

            fout_ip = self.check_fout_name(fout + "_ip")
            fout_port = self.check_fout_name(fout + "_port")

            if tout == 'all' or tout == 'ip':

                fid = open(fout_ip, 'w')

                for ipv4 in sorted(output_ip.keys(), key=lambda ipv4: (int(ipv4.split(".")[0], 10),
                                                                         int(ipv4.split(".")[1], 10),
                                                                         int(ipv4.split(".")[2], 10),
                                                                         int(ipv4.split(".")[3], 10))):


                    for detail in output_ip[ipv4]:
                        fid.write('ip:{:<15} => {}\n'.format(ipv4, detail))

                fid.close()

                click.secho("\nResult stored (sorting by ip):")
                click.secho(fout_ip, fg='green')

            if humanr:
                fid_human = open(fout_ip + "_human", "w")
                for ipv4 in sorted(output_ip.keys(), key=lambda ipv4: (int(ipv4.split(".")[0], 10),
                                                                         int(ipv4.split(".")[1], 10),
                                                                         int(ipv4.split(".")[2], 10),
                                                                         int(ipv4.split(".")[3], 10))):

                    fid_human.write("ip:{:<15} =>\n".format(ipv4))

                    for detail in output_ip[ipv4]:
                        fid_human.write("{:<21} {}\n".format(" ", detail))

                fid_human.close()

                click.secho("\nResult stored (sorting by ip & human readble):")
                click.secho(fout_ip + "_human", fg='green')

            if tout == 'all' or tout == 'port':

                fid = open(fout_port, 'w')

                for index in sorted(output_port.keys()):
                    fid.write("{}\n".format(index))

                    for detail in output_port[index]:
                        fid.write("{:>13}{}\n".format("ip:", detail))

                fid.close()

                click.secho("\nResult stored (sorting by port):")
                click.secho(fout_port, fg='green')


    def sengine(self, fin, fout, api_key, tout):
        """

        :param fin:         input file, contain ip address
        :param fout:        output file, where will be stored result
        :param api_key:     Shodan API key
        :param tout:        type of output file: sort by ip or by port/protocol or both
        :param humanr:      if True - generate additional file, sorted by ip for human readable format
        :return:            dictionary {"ip" : [ports]}
        """

        output_ip = {'No info' : []}
        output_port = {}

        api_shodan = shodan.Shodan(api_key)


        if fout is None:
            fout = fin.name

        fout_ip = self.check_fout_name(fout)  + "_ip"
        fout_port = self.check_fout_name(fout)  + "_port"

        fid = open(fin.name, "r")
        ipv4_hosts = fid.readlines()
        fid.close()

        ipv4_hosts = self.ipv4_sorted(ipv4_hosts)

        fid_ip = open(fout_ip, "w")
        fid_port = open(fout_port, "w")

        with click.progressbar(ipv4_hosts, label="Completed") as hosts:

            for host in hosts:

                try:
                    info = api_shodan.host(host)

                except shodan.exception.APIError as e:

                    if e.value == "Invalid API key":
                        click.secho("Invalid API key: ", nl=False)
                        click.secho("{}".format(api_key), fg="yellow")

                        fid_ip.close()
                        fid_port.close()

                        exit(0)

                    click.secho("\nip:{:<15} : {}".format(host, e.value))
                    # sys.stdout.write("\rip:{:<15} : {}".format(host, e.value))

                    output_ip['No info'].append(host)

                    if tout == 'all' or tout == 'ip':
                        fid_ip.write("ip:{:<15} => {}\n".format(host, "no info"))

                else:

                    click.secho("\nip:", nl=False)
                    click.secho("{}".format(host), fg="cyan")

                    for index in info['data']:
                        click.secho("{:>21}/{}".format(index['transport'], index['port']))

                        if tout == 'all' or tout == 'ip':
                            fid_ip.write("ip:{:<15} => {}/{}\n".format(host, index['port'], index['transport']))

                        port_key = "{}/{}".format(index['port'], index['transport'])

                        if port_key in output_port:
                            output_port[port_key].append(host)
                        else:
                            output_port.update({port_key: [host]})

                        if host in output_ip:
                            output_ip[host].append(port_key)
                        else:
                            output_ip.update({host : [port_key]})

                time.sleep(1)

        click.secho("\nResult search engine 'Shodan' (sorted by ip):")
        click.secho(fout_ip, fg="green")

        for index in sorted(output_port.keys()):

            click.secho('{}'.format(index))
            fid_port.write('{}\n'.format(index))

            for ip in output_port[index]:
                print('{:>12} {}'.format(' ', ip))
                fid_port.write('{:>12} {}\n'.format(' ', ip))

        fid_ip.close()
        fid_port.close()

        click.secho("\nResult search engine 'Shodan' (sorted by port):")
        click.secho(fout_port, fg="green")

        return output_ip


    def urls(self, fin, timeout, ports, fout):
        """
        Check availability url like http://url:port
        :param fin:         input file, contain list of ip/hosts
        :param timeout:
        :param ports:       used ports for check url
        :param fout:        output file, where will be stored results
        :return:            dictionary {'ip' : "{http}:{port}->{message}"}
        """

        url_head = ['http://', 'https://']

        with open(fin.name, "r") as src_data:
            src_hosts = src_data.readlines()

        src_hosts = self.ipv4_sorted(src_hosts)

        if fout is None:
            fout = fin.name

        self.check_fout_name(fout)

        output_url = {}

        with open(self.fout, "w") as fid:

            with click.progressbar(src_hosts, label="Completed") as hosts:

                for ip_addr in hosts:

                    click.secho("\ncheck: {}".format(ip_addr))
                    output_url.update({ip_addr: []})

                    for http in url_head:
                        for port in ports:
                            check_url = http + ip_addr + ":" + str(port)

                            try:
                                html = urllib.request.urlopen(check_url, timeout=timeout)

                            except urllib.request.HTTPError as e:
                                click.secho("{:>20}:{:<6} -> {} {}".format(http.split(':')[0], port, e.msg, e.code))
                                output_url[ip_addr].append("{}:{}->{}:{}".format(http.split(':')[0], port, e.msg, e.code))
                                fid.write("url:{:<30} => {} {}\n".format(check_url, e.msg, e.code))

                            except urllib.error.URLError as e:
                                click.secho("{:>20}:{:<6} -> {}".format(http.split(':')[0], port, e.reason))
                                output_url[ip_addr].append("{}:{}->{}".format(http.split(':')[0], port, e.reason))
                                fid.write("url:{:<30} => {}\n".format(check_url, e.reason))

                            except ssl.CertificateError as e:
                                click.secho("{:>20}:{:<6} -> {}".format(http.split(':')[0], port, e.reason))
                                output_url[ip_addr].append("{}:{}->{}".format(http.split(':')[0], port, e.reason))
                                fid.write("url:{:<30} => {}\n".format(check_url, e))

                            except socket.timeout as e:
                                click.secho("{:>20}:{:<6} -> {}".format(http.split(':')[0], port, e))
                                output_url[ip_addr].append("{}:{}->{}".format(http.split(':')[0], port, e))
                                fid.write("url:{:<30} => {}\n".format(check_url, e))

                            except http_client.RemoteDisconnected as e:
                                click.secho("{:>20}:{:<6} -> {}".format(http.split(':')[0], port, e.filename))
                                output_url[ip_addr].append("{}:{}->{}".format(http.split(':')[0], port, e.filename))
                                fid.write("url:{:<30} => {}\n".format(check_url, e))

                            except Exception as e:
                                click.secho("{:>20}:{:<6} -> {}".format(http.split(':')[0], port, e.args))
                                output_url[ip_addr].append("{}:{}->{}".format(http.split(':')[0], port, e.args))
                                fid.write("url:{:<30} => {}\n".format(check_url, e))

                            else:
                                click.secho("{:>20}:{:<6} -> {}".format(http.split(':')[0], port, html.getcode()))
                                output_url[ip_addr].append("{}:{}->{}".format(http.split(':')[0], port, html.getcode()))
                                fid.write("url:{:<30} => {}".format(check_url, html.getcode()))

        click.secho("\nResult check url:")
        click.secho(self.fout, fg="green")

        return output_url


    @staticmethod
    def _tls_server_check(tls_server):
        """
        Check TLS/SSL server settings using SSlyze library
        documentation: https://nabla-c0d3.github.io/sslyze/documentation/index.html
        :param tls_server:  'ip_address:port'
        :return:            dictionary: msg = {'type'   : "tlscheck",
                                               'status' : "error/ok",
                                               'result' : {'host': "{}:{}".format(host, port),
                                               'msg'    : e.error_message/ dict {tls_result}},
                                               }
        """

        host = tls_server.split(':')[0]
        port = tls_server.split(':')[1]

        server_location = sslyze.ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(host, port)

        try:
            click.secho("\nTry to connect to ", nl=False)
            click.secho("{}:{}".format(host, port), fg="green")
            server_info = sslyze.ServerConnectivityTester().perform(server_location)

        except sslyze.errors.ConnectionToServerFailed as e:


            msg = {'type'   : "tlscheck",
                   'status' : "error",
                   'result' : {'host': "{}:{}".format(host, port),
                                'msg'  : e.error_message},
                   }

            return msg

        else:

            tls_result = {}

            scanner = sslyze.Scanner()

            request_for_check = sslyze.ServerScanRequest(server_info=server_info,
                                                        scan_commands={sslyze.ScanCommand.HEARTBLEED,
                                                                       sslyze.ScanCommand.TLS_COMPRESSION,
                                                                       sslyze.ScanCommand.ROBOT,
                                                                       sslyze.ScanCommand.TLS_1_3_EARLY_DATA,
                                                                       sslyze.ScanCommand.TLS_FALLBACK_SCSV,
                                                                       sslyze.ScanCommand.OPENSSL_CCS_INJECTION,
                                                                       sslyze.ScanCommand.SESSION_RENEGOTIATION,
                                                                       sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES,
                                                                       sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES,
                                                                       sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES,
                                                                       sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES,
                                                                       sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES,
                                                                       sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES}
                                                        )

            scanner.queue_scan(request_for_check)

            for scan_result in scanner.get_results():

                try:
                    res_ssl_v2 = scan_result.scan_commands_results[sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES]

                except KeyError:
                    tls_result.update({"SSL v2": "don't know"})

                else:
                    tls_result.update({"SSL v2": res_ssl_v2.is_tls_protocol_version_supported})

                try:
                    res_ssl_v3 = scan_result.scan_commands_results[sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES]
                except KeyError:
                    tls_result.update({"SSL v3": "don't know"})
                else:
                    tls_result.update({"SSL v3": res_ssl_v3.is_tls_protocol_version_supported})

                try:
                    res_tls_v10 = scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES]
                except KeyError:
                    tls_result.update({"TLS v1.0": "don't know"})
                else:
                    tls_result.update({"TLS v1.0" : res_tls_v10.is_tls_protocol_version_supported})

                try:
                    res_tls_v11 = scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES]
                except KeyError:
                    tls_result.update({"TLS v1.1": "don't know"})
                else:
                    tls_result.update({"TLS v1.1": res_tls_v11.is_tls_protocol_version_supported})

                try:
                    res_tls_v12 = scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES]
                except KeyError:
                    tls_result.update({"TLS v1.2": "don't know"})
                else:
                    tls_result.update({"TLS v1.2": res_tls_v12.is_tls_protocol_version_supported})

                try:
                    res_tls_v13 = scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES]
                except KeyError:
                    tls_result.update({"TLS v1.3": "don't know"})
                else:
                    tls_result.update({"TLS v1.3": res_tls_v13.is_tls_protocol_version_supported})

                try:
                    res_robot = scan_result.scan_commands_results[sslyze.ScanCommand.ROBOT]

                except KeyError:
                    tls_result.update({"Robot vuln": "don't know"})
                    pass
                else:
                    tls_result.update({"Robot vuln": res_robot.robot_result.value})

                try:
                    res_heartbleed = scan_result.scan_commands_results[sslyze.ScanCommand.HEARTBLEED]
                except KeyError:
                    tls_result.update({"Heartbleed": "don't know"})
                else:
                    tls_result.update({"Heartbleed": res_heartbleed.is_vulnerable_to_heartbleed})

                try:
                    res_crime = scan_result.scan_commands_results[sslyze.ScanCommand.TLS_COMPRESSION]
                except KeyError:
                    tls_result.update({"Crime": "don't know"})
                else:
                    tls_result.update({"Crime": res_crime.supports_compression})

                try:
                    res_tls_v13_early_data = scan_result.scan_commands_results[
                        sslyze.ScanCommand.TLS_1_3_EARLY_DATA]
                except KeyError:
                    tls_result.update({"TLS v1.3 early data": "don't know"})
                else:
                    tls_result.update({"TLS v1.3 early data": res_tls_v13_early_data.supports_early_data})

                try:
                    res_downgrade = scan_result.scan_commands_results[sslyze.ScanCommand.TLS_FALLBACK_SCSV]
                except KeyError:
                    tls_result.update({"Downgrade prevention": "don't know"})
                else:
                    tls_result.update({"Downgrade prevention": res_downgrade.supports_fallback_scsv})

                try:
                    res_openssl_inj = scan_result.scan_commands_results[sslyze.ScanCommand.OPENSSL_CCS_INJECTION]
                except KeyError:
                    tls_result.update({"OpenSSL CCS Injection": "don't know"})
                else:
                    tls_result.update({"OpenSSL CCS Injection": res_openssl_inj.is_vulnerable_to_ccs_injection})

                try:
                    res_insecure_reneg = scan_result.scan_commands_results[sslyze.ScanCommand.SESSION_RENEGOTIATION]
                except KeyError:
                    tls_result.update({"Secure Renegotiation Server side" : "don't know"})
                else:
                    tls_result.update({"Secure Renegotiation Server side": res_insecure_reneg.supports_secure_renegotiation})

            msg = {'type'   : "tlscheck",
                   'status' : "ok",
                   'result' : {'host': "{}:{}".format(host, port),
                                'msg'  : tls_result},
                   }

            return msg

    @staticmethod
    def _select_color_msg(what_check, result_tls_check):
        """
        Select color to display result of TLS/SSL server checking
        :param what_check:          one of parameters one of the verification options
        :param result_tls_check:    value of this verification (basically True/False)
        :return:                    ASCII-name of color
        """

        if result_tls_check == "don't know":
            return "white"

        elif what_check in ["SSL v2",
                            "SSL v3",
                            "TLS v1.0",
                            "TLS v1.1",
                            "Heartbleed",
                            "Crime",
                            "OpenSSL CCS Injection"] and (not result_tls_check):
            return "green"

        elif what_check in ["TLS v1.2",
                            "TLS v1.3",
                            "Downgrade prevention",
                            "Secure Renegotiation Server side"] and result_tls_check:
            return "green"

        elif what_check in ["SSL v2",
                            "SSL v3",
                            "TLS v1.0",
                            "TLS v1.1"] and result_tls_check:
            return "red"

        elif what_check in ["TLS v1.3"] and (not result_tls_check):
            return "red"

        else:
            return "white"

    def check_tls(self, fin, ports, fout, th):

        with open(fin.name, "r") as fid:
            tls_servers = fid.readlines()

        tls_servers = self.ipv4_sorted(tls_servers)

        if fout is None:
            fout = fin.name

        self.check_fout_name(fout)

        tls_to_check = []

        for host in tls_servers:

            for port in ports:
                tls_to_check.append("{}:{}".format(host, port))

        tls_result_ret = {}

        with open(self.fout, "w") as fid:

            with concurrent.futures.ProcessPoolExecutor(th) as executor:
                future_tls = {executor.submit(self._tls_server_check, tls_server) : tls_server for tls_server in tls_to_check}

                for future in concurrent.futures.as_completed(future_tls):

                    result_tls_checking = future.result()

                    if result_tls_checking["status"] == "error":
                        click.secho("\n{:<20} -> ".format(result_tls_checking["result"]["host"]), nl=False)
                        click.secho("{}".format(result_tls_checking["result"]["msg"]), fg="yellow")
                        fid.write("ip:{:<20} => error:{}\n".format(result_tls_checking["result"]["host"],
                                                                   result_tls_checking["result"]["msg"]))

                        tls_result_ret.update({result_tls_checking["result"]["host"] :
                                                   {'status' : 'error',
                                                    'msg'    : result_tls_checking["result"]["msg"]}})


                    elif result_tls_checking["status"] == "ok":

                        click.secho("\nResult of checking for: ")
                        click.secho("{:<3} {}".format(" ", result_tls_checking["result"]["host"]), fg="cyan")

                        for item in result_tls_checking["result"]["msg"].keys():

                            fid.write("ip:{:<20} => {} : {}\n".format(result_tls_checking["result"]["host"],
                                                                    item,
                                                                    result_tls_checking["result"]["msg"][item]))

                            color_msg = self._select_color_msg(item, result_tls_checking["result"]["msg"][item])

                            click.secho("{:<5} {:<33}: ".format(" ", item), nl=False)
                            click.secho("{}".format(result_tls_checking["result"]["msg"][item]), fg=color_msg)


                        tls_result_ret.update({result_tls_checking["result"]["host"] :
                                                   {'status' : result_tls_checking["status"],
                                                    'msg'    : result_tls_checking["result"]["msg"]}})


        click.secho("\nResult check TLS server settings:")
        click.secho(self.fout, fg="green")

        return tls_result_ret





CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass

@click.command()
@click.argument('fin', type=click.File('r'))
@click.option('-fout', help='Name of file to store result', default=None)
@click.option('-humanr/-no-humanr', default=False, help="Store result for human read format")
def dns2ip(fin, fout, humanr):
    """
    Find ip address related with dns name
    """
    pwn = Osint()
    pwn.dns2ip_osint(fin, fout, humanr)


@click.command()
@click.argument('weburls', type=click.File('r'))
@click.option('-th', type=click.INT, default=4, help="Max thread for dirb")
def mdirb(weburls, th):
    """
    Run 'dirb' tools for multiply url
    """
    present = os.system('dpkg --status {} | grep "ok installed"'.format("dirb"))

    if not present:
        pwn = Osint()
        pwn.mdirb_osint(weburls, th)
    else:
        click.secho("It seems that tool ", nl=False)
        click.secho("'dirb' ", fg="yellow", nl=False)
        click.secho("don't install")


@click.command()
@click.argument('xml', type=click.File('r'))
@click.option('-fout', help='Name of file to store result', default=None)
@click.option('-tout', type=click.Choice(['ip', 'port', 'all']), default='all', help='Sort by ip, port or both')
@click.option('-humanr/-no-humanr', default=False, help="Store result for human read format")
def xml2txt(xml, fout, tout, humanr):
    """
    Convert xml file from 'masscan' tool to txt file, sorted by ip or by port
    """
    pwn = Osint()
    pwn.xml2txt(xml, fout, tout, humanr)


@click.command()
@click.argument('fin', type=click.File('r'))
@click.option('-fout', help='Name of file to store result', default=None)
@click.option('-api-key', help='API KEY fot Shodan', default='')
@click.option('-tout', type=click.Choice(['ip', 'port', 'all']), default='all', help='Type of output')
@click.option('-humanr/-no-humanr', default=False, help="Store result for human read format")
def sengine(fin, fout, api_key, tout, humanr):
    """
    Get information from search engine. At this moment from Shodan
    """
    pwn = Osint()
    result = pwn.sengine(fin, fout, api_key, tout)

    if humanr:
        with open(pwn.fout + "_humanr", "w") as fid:

                for ipv4 in result.keys():
                    fid.write("ip:{:<15} =>\n".format(ipv4))

                    for port_tcp_udp in result[ipv4]:
                        fid.write("{:<24} {}\n".format(" ", port_tcp_udp))

                click.secho("\nResult search engine 'Shodan' (sorted by ip, human readable):")
                click.secho(pwn.fout + "_humanr", fg="green")


@click.command()
@click.argument('fin', type=click.File('r'))
@click.option('-timeout', help='How many second wait the answer', default=None, type=click.INT)
@click.option('-p', '--ports', help='Scan Ports', multiple=True, default=[80])
@click.option('-fout', help='Name of file to store result', default=None)
@click.option('-humanr/-no-humanr', default=False, help="Store result for human read format")
def urls(fin, timeout, ports, fout, humanr):
    """
        \b
    Check availability of web-interface/web-resource;
    very similar like 'curl -I http://some_site'

    """
    pwn = Osint()
    urls_result = pwn.urls(fin, timeout, ports, fout)

    if humanr:

        with open(pwn.fout + "_humanr", "w") as fid:

            for ip in urls_result.keys():
                fid.write("{}\n".format(ip))

                for item in urls_result[ip]:
                    fid.write("{:>20}:{:<5} -> {}\n".format(item.split("->")[0].split(":")[0],
                                                            item.split("->")[0].split(":")[1],
                                                            item.split("->")[1]))

        click.secho("\nResult check url (human readable format):")
        click.secho(pwn.fout + "_humanr", fg="green")


@click.command()
@click.argument('fin', type=click.File('r'))
@click.option('-p', '--ports', help='Scan Ports', multiple=True, default=[443])
@click.option('-fout', help='Name of file to store result', default=None)
@click.option('-th', type=click.INT, default=4, help="Max thread")
@click.option('-humanr/-no-humanr', default=False, help="Store result for human read format")
def tlscheck(fin, ports, fout, th, humanr):
    """
    \b
    Check TLS/SSL server setting
    Fot this used sslyze library: https://github.com/nabla-c0d3/sslyze
    """
    pwn = Osint()
    result = pwn.check_tls(fin, ports, fout, th)

    if humanr:
        with open(pwn.fout + "_humanr", "w") as fid:
            for host in result.keys():
                fid.write("\nip:{} ->\n".format(host))

                if result[host]["status"] == "error":
                    fid.write("{:<24} {}\n".format(" ", result[host]["msg"]))
                elif result[host]["status"] == "ok":
                    for item in result[host]["msg"].keys():
                        fid.write("{:>32} : {}\n".format(item, result[host]["msg"][item]))

        click.secho("\nResult check TLS server settings (human readable format):")
        click.secho(pwn.fout + "_humanr", fg="green")



cli.add_command(dns2ip)
cli.add_command(mdirb)
cli.add_command(xml2txt)
cli.add_command(sengine)
cli.add_command(urls)
cli.add_command(tlscheck)


if __name__ == '__main__':
    cli()