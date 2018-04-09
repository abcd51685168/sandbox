__author__ = 'polyhawk'
from lib.cuckoo.common.abstracts import Signature
class Black_Domain(Signature):
    name = "black_domain"
    description = "Domain has been identified as bad reputation"
    severity = 3
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
        for domain in self.results["network"]["domains"]:
            if "dbAnalyzer" in domain["result"]:
                if domain["result"]["dbAnalyzer"][0] == "1":

                    return True

                #domain["result"].keys()[0]
    
        for host in self.results["network"]["hosts"]:
            if "dbAnalyzer" in host["result"]:
                if host["result"]["dbAnalyzer"][0] == "1":
                    return True

        for tcp in self.results["network"]["tcp"]:
            if "dbAnalyzer" in tcp["result"]:
                if tcp["result"]["dbAnalyzer"][0] == "1":
                    return True
                
        for udp in self.results["network"]["udp"]:
            if "dbAnalyzer" in udp["result"]:
                if udp["result"]["dbAnalyzer"][0] == "1":
                    return True

               
        
