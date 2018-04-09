#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import sys
import os

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", ".."))

from lib.cuckoo.common.abstracts import Dumi
from lib.cuckoo.common.constants import UTILS_ROOT

sys.path.append(UTILS_ROOT)
from blackwhitelist.bwlist import query_dumi

log = logging.getLogger(__name__)


class WbAnalyzer(Dumi):
    order = 1

    def run(self):
        """return None or Signature"""
        self.key = "wbAnalyzer"
        result = []

        try:
            result = query_dumi(self.task["target"])
        except Exception as e:
            log.error("wbAnalyzer failed, msg %s" % e)
        return result

