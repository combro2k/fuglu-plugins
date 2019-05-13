
# -*- coding: UTF-8 -*-
#   Copyright 2018-2019 Martijn van Maurik
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys, socket, re, os

from fuglu.shared import ScannerPlugin, DUNNO, DEFER, REJECT
from IPy import IP
from dns.resolver import Resolver, NXDOMAIN, NoNameservers, Timeout, NoAnswer
from threading import Thread

"""
    Copied from github repo

    @source https://github.com/drscream/rblwatch
"""
class Lookup(Thread):
    def __init__(self, host, dnslist, listed, resolver):
        Thread.__init__(self)
        self.host = host
        self.listed = listed
        self.dnslist = dnslist
        self.resolver = resolver

    def run(self):

        try:
            host_record = self.resolver.query(self.host, "A")
            if len(host_record) > 0:
                self.listed[self.dnslist]['LISTED'] = True
                self.listed[self.dnslist]['HOST'] = host_record[0].address
                text_record = self.resolver.query(self.host, "TXT")
                if len(text_record) > 0:
                    self.listed[self.dnslist]['TEXT'] = "\n".join(
                        [resp.decode('utf-8') for resp in
                            text_record[0].strings])
            self.listed[self.dnslist]['ERROR'] = False

            if 'query refused' in self.listed[self.dnslist]['TEXT'].lower():
                self.listed[self.dnslist]['LISTED'] = False
                self.listed[self.dnslist]['ERROR'] = True

        except NXDOMAIN:
            self.listed[self.dnslist]['ERROR'] = True
            self.listed[self.dnslist]['ERRORTYPE'] = NXDOMAIN
        except NoNameservers:
            self.listed[self.dnslist]['ERROR'] = True
            self.listed[self.dnslist]['ERRORTYPE'] = NoNameservers
        except Timeout:
            self.listed[self.dnslist]['ERROR'] = True
            self.listed[self.dnslist]['ERRORTYPE'] = Timeout
        except NameError:
            self.listed[self.dnslist]['ERROR'] = True
            self.listed[self.dnslist]['ERRORTYPE'] = NameError
        except NoAnswer:
            self.listed[self.dnslist]['ERROR'] = True
            self.listed[self.dnslist]['ERRORTYPE'] = NoAnswer

"""
    Copied from github repo, and adjusted to special needs

    @source https://github.com/drscream/rblwatch
"""
class RBLSearch(object):
    def __init__(self, lookup_host):
        self.lookup_host = lookup_host
        self._listed = None
        self.resolver = Resolver()
        self.resolver.timeout = 0.2
        self.resolver.lifetime = 1.0

    def search(self, RBLS=[]):
        if self._listed is not None:
            pass
        else:

            try:
                ip = IP(self.lookup_host)
            except ValueError:
                ip = None

            self._listed = {'SEARCH_HOST': self.lookup_host}

            if ip:

                host = ip.reverseName()
                if ip.version() == 4:
                    host = re.sub('.in-addr.arpa.', '', host)
                elif ip.version() == 6:
                    host = re.sub('.ip6.arpa.', '', host)
            else:

                try:
                    socket.gethostbyname(self.lookup_host)
                    host = self.lookup_host
                except socket.gaierror:
                    self._listed['SEARCH_HOST'] = {
                        'ERROR': True,
                        'ERRORTYPE': socket.gaierror
                    }
                except socket.herror:
                    self._listed['SEARCH_HOST'] = {
                        'ERROR': True,
                        'ERRORTYPE': socket.herror
                    }

            if 'ERROR' in self._listed['SEARCH_HOST']:
                return self._listed

            threads = []

            lists_to_check = RBLS

            for LIST in lists_to_check:
                self._listed[LIST] = {'LISTED': False}
                query = Lookup(
                    "%s.%s" % (host, LIST), LIST, self._listed, self.resolver)
                threads.append(query)
                query.start()
            for thread in threads:
                thread.join()
        return self._listed
    listed = property(search)

"""

"""
class RBLLookupPlugin(ScannerPlugin):
    _RBLS = None
    _loadtime = None

    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars = {
            'rbllist': {
                'default': '/etc/fuglu/rbllist.list',
                'description': "File which contains the used RBL lists",
            },
        }

    def get_time_stamp(self, filename):
        if not os.path.isfile(filename):
            self.logger().error('Could not open %s' % (filename))
            return False
        statinfo = os.stat(filename)
        return statinfo.st_ctime

    @property
    def RBLS(self):
        rbllist = self.config.get(self.section, 'rbllist')
        if self._RBLS is None or self.get_time_stamp(rbllist) > self._loadtime:
            self._loadtime = self.get_time_stamp(rbllist)
            self._RBLS = []
            with open(rbllist) as handle:
                RBLS = handle.read().splitlines(False)
                for rbl in RBLS:
                    if not rbl.startswith('#'):
                        self._RBLS.append(rbl)
        return self._RBLS

    @property
    def logger(self):
        return self._logger

    def examine(self, suspect):
        try:
            if suspect.clientinfo:
                helo, ip, revdns = suspect.clientinfo
            else:
                ip = ''

            if len(ip) > 1:
                pat = re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
                is_ip_address = pat.match(ip)
                if not is_ip_address:
                    try:
                        ip = socket.gethostbyname(helo)
                        self.logger().error("Hostname %s resolved to ip %s" % (host, ip))
                    except socket.error:
                        self.logger().error("IP %s can't be resolved" % ip)
                        ip = ""
                if ip:
                    searcher = RBLSearch(ip)
                    listed = searcher.search(self.RBLS)

                    for key in listed:
                        if not key == 'SEARCH_HOST' and not listed[key]['ERROR']:
                            return REJECT, 'RBL Blacklisted: %s' % (listed[key]['TEXT'])
        except Exception as e:
            self.logger().error(e)

        return DUNNO
