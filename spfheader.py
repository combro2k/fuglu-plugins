
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
#

"""
 Add SPF header to the email
"""

from fuglu.shared import ScannerPlugin,DUNNO

class SPFHeaderPlugin(ScannerPlugin):
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)

    def examine(self,suspect):
        result = suspect.get_tag('SPF.status', 'unknown')
        reason = suspect.get_tag('SPF.explanation', 'unkown')

        if result != 'none':
            received_spf = "%s (%s)" % (result, reason)
        else:
            received_spf = result

        suspect.addheader('Received-SPF', received_spf, immediate=True)

        return DUNNO

    def __str__(self):
        return "SPF Header"
