from itertools import count
from traceback import print_tb
from turtle import ht
import pyshark
from scapy.all import *
from urllib.parse import unquote


def rate_limit_get_post(path):
        print(path)
        count=0
        cap = pyshark.FileCapture(path)
        recent=''
        for i in cap:
            if(i.ip.src == recent):
                count=count+1
            if(recent == ''):
                recent=i.ip.src
            if(count==10):
                print("Possible DDOS from "+i.ip.src)
                count=0
                recent=''


class Web_vulns(object):
    path=''
    network_data={}
    
    def __init__(self, data,path):
        self.network_data=data
        self.path=path

    def print_data(self):
        print(self.network_data)
        print(self.path)


    def sqli_get_post(self):
        founded_data=[]
        impcat=0
        attack="SQL Injection"
        blacklist=["\"","'","select","*","from","information_schema","-","#","/*","like","%","_","/*","concat","tables","columns","(",")","or","and","join","union","exp","sleep","update","drop","floor","rand"]
        if "Request URI Query Parameter" in self.network_data: #get parameter
            unqouted_data=unquote(self.network_data['Request URI Query Parameter']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    founded_data.append(i)
                    impcat=impcat+1
        elif "Form item" in self.network_data:
            unqouted_data=unquote(self.network_data['Form item']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    founded_data.append(i)
                    impcat=impcat+1
        
        if impcat:
            return {"Attack_found":attack,"impact":impcat,"type":"Web based Vulnerability - Server Side","endpoint":self.network_data["Full request URI"],"malicious_inputs":founded_data}
    


    def xss_get_post(self):
        impcat=0
        founded_data=[]
        attack="XSS- Cross Site Scripting"
        blacklist=["<",">","=","javscript:","script","alert","document","window","cookie","iframe","src","srcdoc","alert","(",")","<!--","-->","img","object","form","[","]","'","\"","onload","onerror","onmouseover","on","$","eval","fetch","XMLHttpRequest"]
        if "Full request URI" in self.network_data:
            unqouted_data=unquote(self.network_data['Full request URI']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    founded_data.append(i)
                    impcat=impcat+1
        if "Request URI Query Parameter" in self.network_data: #get parameter
            unqouted_data=unquote(self.network_data['Request URI Query Parameter']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    founded_data.append(i)
                    impcat=impcat+1
        elif "Form item" in self.network_data:
            unqouted_data=unquote(self.network_data['Form item']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    impcat=impcat+1
        
        if impcat:
            return {"Attack_found":attack,"impact":impcat,"type":"Web based Vulnerability - client side","endpoint":self.network_data["Full request URI"],"malicious_inputs":founded_data}

    def lfi_get_post(self):
        impcat=0
        founded_data=[]
        attack="lfi- Localfile Inclusion"
        blacklist=[".","../","//","/",".","\\","php:","expect:","zip:","data:","file:","phar:"]
        if "Request URI Query Parameter" in self.network_data: #get parameter
            unqouted_data=unquote(self.network_data['Request URI Query Parameter']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    founded_data.append(i)
                    impcat=impcat+1
        elif "Form item" in self.network_data:
            unqouted_data=unquote(self.network_data['Form item']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    impcat=impcat+1
                    founded_data.append(i)
        
        if impcat:
            return {"Attack_found":attack,"impact":impcat,"type":"Web based Vulnerability - Server Side","endpoint":self.network_data["Full request URI"],"malicious_inputs":founded_data}


    def command_injection_get_post(self):
        impcat=0
        founded_data=[]
        attack="COMMAND Injection"
        blacklist=["active","add","arp","at","call","chdir","cmd","copy","date","del","dir","exec","dns","extend","ftp","delete",";",">","<","&","*","~","/",".","|","ls","pwd","cd","mkdir","mv","cp","rm","touch","in","cat","echo","man","less","whoami","tar","wget","curl","ssh","ps","ifconfig","sudo","nc","pwd","la"]
        if "Request URI Query Parameter" in self.network_data: #get parameter
            unqouted_data=unquote(self.network_data['Request URI Query Parameter']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    founded_data.append(i)
                    impcat=impcat+1
        elif "Form item" in self.network_data:
            unqouted_data=unquote(self.network_data['Form item']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    founded_data.append(i)
                    impcat=impcat+1
        
        if impcat:
            return {"Attack_found":attack,"impact":impcat,"type":"Web based Vulnerability - Server Side","endpoint":self.network_data["Full request URI"],"malicious_inputs":founded_data}




    def ssrf_get_post(self):
        impcat=0
        founded_data=[]
        attack="SSRF Server-Side-Request-Forgery"
        blacklist=["metadata","100.100.100.200","192.0.0.192","computeMetadata","metadata.google.internal","meta-data","latest","gopher:","ldap:","169.254.169.254","o177.0.0.1","0o177.0.0.1","q177.0.0.1","0177.0.0.1","2852039166","3232235777","3232235521","2130706433","127.0.0.1","127.0.0.0","localhost","0.0.0.0","http","https","ftp","[","]","[]","[::]",":",":80",":25",":22",":2375"]
        if "Request URI Query Parameter" in self.network_data: #get parameter
            unqouted_data=unquote(self.network_data['Request URI Query Parameter']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    founded_data.append(i)
                    impcat=impcat+1
        elif "Form item" in self.network_data:
            unqouted_data=unquote(self.network_data['Form item']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    founded_data.append(i)
                    impcat=impcat+1
        
        if impcat:
            return {"Attack_found":attack,"impact":impcat,"type":"Web based Vulnerability - Server Side","endpoint":self.network_data["Full request URI"],"malicious_inputs":founded_data}



    def xxe_get_post(self):
        impcat=0
        founded_data=[]
        attack="XXE - XML external entity injection"
        blacklist=["xml"," ?-->","<!--?","SYSTEM","&",";","ENTITY"]
        if "Request URI Query Parameter" in self.network_data: #get parameter
            print(self.network_data['Request URI Query Parameter'])
            unqouted_data=unquote(self.network_data['Request URI Query Parameter']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    founded_data.append(i)
                    impcat=impcat+1
        elif "Form item" in self.network_data:
            unqouted_data=unquote(self.network_data['Form item']).lower()
            for i in blacklist:
                if(i in unqouted_data):
                    founded_data.append(i)
                    impcat=impcat+1
        
        if impcat:
            return {"Attack_found":attack,"impact":impcat,"type":"Web based Vulnerability - Server Side","endpoint":self.network_data["Full request URI"],"malicious_inputs":founded_data}

        


def http_dict_builder(body):
    arr=body.replace("Layer HTTP:","").replace("\t","").splitlines()
    out=dict()
    for i in arr:
        if ":" in i:
            key,value=i.split(":",1)
            out[key]=value
    return out



path = "pcap/network_log_1.pcap" 
cap = pyshark.FileCapture(path)
for i in cap:
    #check if its http packet
    if 'http' and 'URLENCODED-FORM' in i:
        try:
            #Object
            http_data = http_dict_builder(str(i["http"]))
            if 'Status Code' not in http_data:
                http_data.update(http_dict_builder(str(i["URLENCODED-FORM"])))
                http_data = Web_vulns(http_data,path)
                print("__________________________formated packets post methord___________________________")
                print(http_data.sqli_get_post())
                print(http_data.xss_get_post())
                print(http_data.lfi_get_post())
                print(http_data.command_injection_get_post())
                print(http_data.ssrf_get_post())
                print(http_data.xxe_get_post())
                #http_data.print_data()

            #accessing normal http headers
            if hasattr(i.http, 'request_line'):  
                                lists_request = cap[8].http.request_line.all_fields
                                map={}
                                for _, request_header in enumerate(lists_request):
                                    header_key = request_header.showname_key
                                    header_value = request_header.showname_value.replace('\\n', '').replace('\\r', '')
                                    map[header_key]=header_value
        except :
            print()

    elif 'URLENCODED-FORM' not in i and 'http' in i:
        try:
            http_data = http_dict_builder(str(i["http"]))
            if 'Status Code' not in http_data:
                http_data = Web_vulns(http_data)
                print("__________________________formated packets get methord______________________")
                print(http_data.sqli_get_post())
                print(http_data.xss_get_post())
                print(http_data.lfi_get_post())
                print(http_data.command_injection_get_post())
                print(http_data.ssrf_get_post())
                print(http_data.xxe_get_post())
                #http_data.print_data()
            #accessing normal http headers
            if hasattr(i.http, 'request_line'):  
                                lists_request = cap[8].http.request_line.all_fields
                                map={}
                                for _, request_header in enumerate(lists_request):
                                    header_key = request_header.showname_key
                                    header_value = request_header.showname_value.replace('\\n', '').replace('\\r', '')
                                    map[header_key]=header_value
        except :
            print()


#rate_limits
rate_limit_get_post(path)