# Copyright (C) 2015 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class StealthNetwork(Signature):
    name = "stealth_network"
    description = "Network activity detected but not expressed in API logs"
    severity = 3
    categories = ["stealth"]
    authors = ["Accuvant"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.foundnetwork = False
        self.handles = dict()
        self.lastprocess = 0
        self.stealth_files = []
        self.is_office = False
        office_pkgs = ["docx","ppt","doc","xls","eml","pptx","xlsx"]
        if any(e in self.results["target"]["file"]["name"] for e in office_pkgs):
            self.is_office = True

    filter_categories = set(["network"])

    def on_call(self, call, process):
        self.foundnetwork = True

    def on_complete(self):
        initialproc = self.get_initial_process()
        if self.is_office:
            return False
        if "network" in self.results:
            if ((("hosts" in self.results["network"]) and len(self.results["network"]["hosts"]) > 0) or
                (("domains" in self.results["network"]) and len(self.results["network"]["domains"]) > 0)) and initialproc and not self.foundnetwork:
                return True


        return False
