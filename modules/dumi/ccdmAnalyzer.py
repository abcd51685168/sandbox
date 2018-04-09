#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
from ctypes import cdll

from lib.cuckoo.common.abstracts import Dumi
from lib.cuckoo.common.constants import CONTENT_ROOT, UTILS_ROOT

log = logging.getLogger(__name__)

try:
    libccdm = cdll.LoadLibrary(os.path.join(UTILS_ROOT, "ccdm/libccdm.so"))
    log.debug("load libccdm.so successfully")
except Exception as e:
    raise EnvironmentError("can not load libccdm.so")


class CcdmAnalyzer(Dumi):
    order = 5

    def run(self):
        """return None or Signature"""
        self.key = "ccdmAnalyzer"
        result = []
        markov_path = os.path.join(CONTENT_ROOT, self.options.markov_path)
        tld_path = os.path.join(CONTENT_ROOT, self.options.tld_path)
        ngram_path = os.path.join(CONTENT_ROOT, self.options.ngram_path)
        hmm_path = os.path.join(CONTENT_ROOT, self.options.hmm_path)
        svm_path = os.path.join(CONTENT_ROOT, self.options.svm_path)
        ret_code = libccdm.pecker_ccdm_init(markov_path, tld_path, ngram_path, hmm_path, svm_path)
        # ret_code: 0---initialize successfully    else--false
        if ret_code:
            log.error("libccdm.pecker_ccdm_init failed, ret_code:%s" % ret_code)
        else:
            # task.target: <type 'unicode'>, so you get it.
            result = str(libccdm.pecker_ccdm_match(str(self.task["target"]))).split()
            log.debug("libccdm.pecker_ccdm_init successfully")
        return result
