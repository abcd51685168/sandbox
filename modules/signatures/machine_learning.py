__author__ = 'polyhawk'
from lib.cuckoo.common.abstracts import Signature
class Black_Domain(Signature):
    name = "machine_learning"
    description = "Domain has been identified as bad reputation by using machine learning "
    severity = 2
    categories = ["bad_reputaion"]
    authors = ["polyhawk"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.foundnetwork = False

    filter_categories = set(["network"])

    def on_call(self, call, process):
        self.foundnetwork = True

    def on_complete(self):
        initialproc = self.get_initial_process()
        whitelists = ["ipv6.msftncsi.com"]


        for hosts in self.results["network"]["hosts"]:
            if "ccdmAnalyzer"and "domain" in hosts["result"]:
                if hosts["result"]["ccdmAnalyzer"][0] == "1" and hosts["domain"] not in whitelists:
                    return True
                else:
                    return False

        for hosts in self.results["network"]["domains"]:
            if "ccdmAnalyzer"and "domain" in hosts["result"]:
                if hosts["result"]["ccdmAnalyzer"][0] == "1" and hosts["domain"] not in whitelists:
                    return True
                else:
                    return False



               
        
