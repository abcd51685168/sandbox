#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
from ctypes import cdll, string_at
from threading import Lock
import sys

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CONTENT_ROOT, UTILS_ROOT

log = logging.getLogger(__name__)
fmt_lock = Lock()

file_type_paras = Config().get("file_type")
fmt_lock.acquire()
try:
    libpdfmt = cdll.LoadLibrary(os.path.join(UTILS_ROOT, file_type_paras.fmt_path))
    log.info("cdll.LoadLibrary %s" % file_type_paras.fmt_path)
except:
    raise EnvironmentError("Could not load {0}".format(file_type_paras.fmt_path))

# retcode——0 successful
retcode = libpdfmt.pd_global_fmt_init()
if retcode:
    log.error("libpdfmt.pd_global_fmt_init failed, retcode: %d" % retcode)
else:
    log.debug("libpdfmt.pd_global_fmt_init successfully")

ret_code = libpdfmt.pd_global_fmt_load_lib(os.path.join(CONTENT_ROOT, file_type_paras.sig_path))
fmt_lock.release()
if ret_code:
    log.error("libpdfmt.pd_global_fmt_load_lib failed, return code:%s" % ret_code)
else:
    log.debug("libpdfmt.pd_global_fmt_load_lib successfully")


def pd_fmt_file(file_path):
    """File type identification.
    @param file_path: file_path.
    @return: [file_type<type 'int'>, ext_match<type 'int'>, lib_ext<type 'str'>].
    """
    if not os.path.exists(file_path):
        return False

    types = {0: "ANY", 1: "ERROR", 2: "EMPTY", 3: "TEXT ASCII", 4: "TEXT UTF8",
             5: "TEXT UTF16LE", 6: "TEXT UTF16BE", 7: "BINARY DATA"}
    fmt_lock.acquire()
    file_type = libpdfmt.pd_global_fmt_file(file_path)    # <type 'int'>
    ext_match = libpdfmt.pd_global_fmt_get_ext_match()
    lib_name = libpdfmt.pd_global_fmt_get_lib_name()
    if lib_name:
        lib_name = string_at(lib_name)
    else:
        lib_name = types.get(file_type)
    fmt_lock.release()
    return [file_type, ext_match, lib_name]


if __name__ == '__main__':
    result = pd_fmt_file("/tmp/tank.exe")
    print result, type(result[0])
