#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import logging

from lib.cuckoo.common.abstracts import StaticScan
from lib.cuckoo.common.constants import UTILS_ROOT

log = logging.getLogger(__name__)

JSUNPACK_PATH = os.path.join(UTILS_ROOT, "jsunpack")
sys.path.append(JSUNPACK_PATH)

try:
    from jsunpackn import main
except Exception as e:
    raise EnvironmentError('could not import jsunpack: %s' % e)


class JsunpackAnalyzer(StaticScan):
    order = 3

    def run(self):
        """return None or Signature"""
        self.key = "jsunpack"
        curdir = os.getcwd()
        os.chdir(JSUNPACK_PATH)
        try:
            result = main(self.task["target"])
        except Exception as e:
            log.exception('Task #%d jsunpack scan error: %s' % (self.task["id"], e))
            return None
        os.chdir(curdir)

        js = result.rooturl[result.url]
        signature = None
        log.debug("Task #%d jsunpack result: %s" % (self.task["id"], js.msg))
        for printable, severity, sig in js.msg:
            if 5 < js.malicious and severity == js.malicious:
                signature = sig
                if "printSeps" in signature:
                    signature = signature.replace("printSeps" , "")
                    signature=signature.replace("detected" , "")
                elif "Utilprintf" in signature:
                    signature = signature.replace("Utilprintf" , "")
                    signature=signature.replace("detected" , "")
                break
        return signature
