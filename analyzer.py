import os,sys,requests,argparse,ast
from AssociatedAnalyzer.functions import bcolors
from AssociatedAnalyzer.log import msg


def print_des():
    print(f"""{bcolors.YELLOW}

                                         _       _           _ _______ _                    _                        _                    
                /\                      (_)     | |         | |__   __| |                  | |     /\               | |                   
               /  \   ___ ___  ___   ___ _  __ _| |_ ___  __| |  | |  | |__  _ __ ___  __ _| |_   /  \   _ __   __ _| |_   _ _______ _ __ 
              / /\ \ / __/ __|/ _ \ / __| |/ _` | __/ _ \/ _` |  | |  | '_ \| '__/ _ \/ _` | __| / /\ \ | '_ \ / _` | | | | |_  / _ \ '__|
             / ____  \__ \__ \ (_) | (__| | (_| | ||  __/ (_| |  | |  | | | | | |  __/ (_| | |_ / ____ \| | | | (_| | | |_| |/ /  __/ |   
            /_/    \_\___/___/\___/ \___|_|\__,_|\__\___|\__,_|  |_|  |_| |_|_|  \___|\__,_|\__/_/    \_\_| |_|\__,_|_|\__, /___\___|_|   
                                                                                                                        __/ |             v1.0
                                                                                                                        |___/ 
            Author : OsmanKandemir{bcolors.ENDC}
            
            """)
print_des()


sys.stdout = open(os.devnull, 'w')

from AssociatedAnalyzer.indicator.indicator import Indicator

sys.stdout = sys.__stdout__

PATH: str = os.getcwd()


class AnalyzerException(Exception):
    """
    Analyzer exception class
    """
    def __init__(self, message):
        """
        AnalyzerException class constructor
        :param message: string
        """
        self.message_ = message

        Exception.__init__(self, '%s' % (self.message_))


class Analyzer(object):

    def __init__(self,domain,malicious_domains,malicious_ips):
        """
        Analyzer main class
        :param domain: list
        :param malicious_domains_: list
        :param malicious_ips_ : list
        """
        self.domain_: list = domain
        self.malicious_domains_: list = malicious_domains if malicious_domains else [line.strip() for line in open(PATH + "/AssociatedAnalyzer/malicious-domains-ips/MaliciousDomains.txt","r")]
        self.malicious_ips_: list = malicious_ips if malicious_ips else [line.strip() for line in open(PATH + "/AssociatedAnalyzer/malicious-domains-ips/MaliciousIps.txt","r")]
        try:
            self.data:list  = self.IndicatorData()
        except:
            raise AnalyzerException("Error - Indicator-Intelligence can not fetch data.")
            sys.exit()

                   
    def IndicatorData(self) -> dict:
        """

        Get Releated Domains and IPv4 Addresses with the help of Indicator-Intelligence v1.1.1

        """
        msg(f"{bcolors.OKBLUE} Fetching related Domains and IPs.{bcolors.ENDC}" )
        sys.stdout = open(os.devnull, 'w')
        result = Indicator([self.domain_[0]],json=True)
        sys.stdout = sys.__stdout__
        return result[0]

    def IndicatorParseData(self) -> list:
        """
        
        Merge IP and Domains in two separate lists after split related Domains and IPv4 data from the Indicator-Intelligence v1.1.1 application.

        """
        IPAddresses, DomainAddresses, MergeListIps = [], [], []
        for data in ast.literal_eval(self.data):
            DomainAddresses.append(data["DOMAIN"])
            MergeListIps.append(data["IPs"])
        for Ip in MergeListIps:
            IPAddresses.extend(Ip)
        return DomainAddresses,IPAddresses

    def Compare(self,data:tuple) -> list:
        """
        
        Compare Malicious Domains and IPv4 addresses.

        """
        if data:
            DomainAddresses,IPAddresses = data
            msg(f"{bcolors.OKBLUE} Associated Domains and IPs were compared with malicious Domains and IPs.{bcolors.ENDC}" )
            return list(set(DomainAddresses) & set(self.malicious_domains_)), list(set(IPAddresses) & set(self.malicious_ips_))
        else:
            return []

    def run(self):
        return self.Compare(self.IndicatorParseData())

    @property
    def domain(self):
        return self.domain_

    @property
    def malicious_domains(self):
        return self.malicious_domains_
    
    @property
    def malicious_ips(self):
        return self.malicious_ips_

    
    def __str__(self):
        return f"Analyzer"
    
    
    def __repr__(self):
        return 'Analyzer(domain_=' + str(self.domain_) + ' ,malicious_ips_=' + self.malicious_ips_ + ' ,self.malicious_domains_=' + self.malicious_domains_ +')'

def print_result(data,json) -> None:
    if not json:
        for data_ in data:
            if data_:
                msg(f"{bcolors.LOG}FOUND{bcolors.ENDC}{bcolors.HEADER} -> Malicious Association : {bcolors.ENDC}{bcolors.YELLOW}{data_}{bcolors.ENDC}" )
            if not data_:
                msg(f"{bcolors.LOG}NOT FOUND{bcolors.ENDC}{bcolors.HEADER} -> Malicious Association : {bcolors.ENDC}{bcolors.YELLOW}{data_}{bcolors.ENDC}" )
            else:
                continue
    else:
        print({"DOMAINS":data[0],"IPs":data[1]})


def STARTS():

    malicious_ips = None
    malicious_domains = None

    parser = argparse.ArgumentParser()
    parser.add_argument("-d","--domain", nargs='+', required="True", help="Input domain to scan. --domain sample.com")
    parser.add_argument("-i",'--IPsFile', type= argparse.FileType('r'), nargs='?', const='', help="Malicious Domains List to Compare. -i SampleMaliciousIPs.txt")
    parser.add_argument("-t",'--DomainsFile', type=argparse.FileType('r'), nargs='?', const='', help="Malicious IPs List to Compare -t SampleMaliciousDomains.txt")
    parser.add_argument("-o","--json", action = "store_true", help="JSON output. --json")

    args = parser.parse_args()

    if args.IPsFile:malicious_ips = [ips.strip() for ips in args.IPsFile]
    if args.DomainsFile:malicious_domains = [domains.strip() for domains in args.DomainsFile]
    json = args.json if args.json else None


    print_result(Analyzer(args.domain, malicious_domains, malicious_ips).run(),json)



if __name__ == "__main__":
    STARTS()
    sys.exit()