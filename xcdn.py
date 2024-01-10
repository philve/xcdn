#!/usr/bin/env python3
#############################################################
###                                                  
###   ▄▄▄▄                ▄▄▄     ▄▄▄▄    ▀      ▄   
###  ▀   ▀█ ▄   ▄  ▄▄▄▄     █    ▄▀  ▀▄ ▄▄▄    ▄▄█▄▄ 
###    ▄▄▄▀  █▄█   █▀ ▀█    █    █  ▄ █   █      █   
###      ▀█  ▄█▄   █   █    █    █    █   █      █   
###  ▀▄▄▄█▀ ▄▀ ▀▄  ██▄█▀  ▄▄█▄▄   █▄▄█  ▄▄█▄▄    ▀▄▄ 
###                █                                 
###                ▀                                 
###                                                          
### name: xcdn.py
### function: try to get the actual ip behind cdn
### date: 2016-11-05
### author: quanyechavshuo
### blog: http://3xp10it.cc
#############################################################
# usage:python3 xcdn.py www.baidu.com
import time
import os
try:
    import exp10it
except:
    os.system("pip3 install exp10it")    
    # os.system("pip3 install exp10it -U --no-cache-dir")    
from exp10it import figlet2file
try:
    figlet2file("3xp10it",0,True)
except:
    pass
time.sleep(1)

from exp10it import CLIOutput
from exp10it import get_root_domain
from exp10it import get_string_from_command
from exp10it import get_http_or_https
from exp10it import post_request
from exp10it import get_request
from exp10it import checkvpn
import sys
import re

class Xcdn(object):

    def __init__(self,domain):
        # Must be guaranteed to be connected to VPN, and this tool must be used under the conditions that can ping through Google. Otherwise, some Domain will cause
        #, CheckVPN returns 1
        while 1:
            if checkvpn()==1:
                break
            else:
                time.sleep(1)
                print("vpn is off,connect vpn first")
        if domain[:4]=="http":
            print("domain format error,make sure domain has no http,like www.baidu.com but not \
http://www.baidu.com")
            sys.exit(0)
        #First of all, ensure that there are no items related to Domain in the hosts file, there is deletion related
        domainPattern=domain.replace(".","\.")
        #\N, SED matching \n is special
        #http://stackoverflow.com/questions/1251999/how-can-i-replace-a-newline-n-using-sed
        command="sudo sed -ri 's/.*\s+%s//' /etc/hosts" % domainPattern
        os.system(command)

        self.domain=domain
        self.http_or_https=get_http_or_https(self.domain)
        print('domain的http或https是:%s' % self.http_or_https)
        result=get_request(self.http_or_https+"://"+self.domain,'seleniumPhantomJS')
        self.domain_title=result['title']
       # Below calls the GET_ACTUAL_IP_FROM_DOMain function equivalent to the main function
        actual_ip = self.get_actual_ip_from_domain()
        if actual_ip != 0:
            print("恭喜,%s的真实ip是%s" % (self.domain, actual_ip))
        #The following is used to store the key return value
        self.return_value=actual_ip

        
    def domain_has_cdn(self):
        # Detect whether Domain has CDN
        # When there is a CDN, return a dictionary, if the CDN is a cloudflare, return {'Has_cdn': 1, 'is_Cloud_flare': 1}
        # Otherwise, return {'has_cdn': 1, 'is_cloud_flare': 0} or {'has_cdn': 0, 'is_cloud_flare': 0}
        import re
        CLIOutput().good_print("现在检测domain:%s是否有cdn" % self.domain)
        has_cdn = 0
        # The NS record is the same as the MX record, and the top domain name must be checked, eg.dig +short www.baidu.com ns dig +short Baidu.com NS
        result = get_string_from_command("dig ns %s +short" % get_root_domain(self.domain))
        pattern = re.compile(
            r"(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)", re.I)
        cloudflare_pattern = re.compile(r"cloudflare", re.I)
        if re.search(pattern, result):
            if re.search(cloudflare_pattern, result):
                print("has_cdn=1 from ns,and cdn is cloudflare")
                return {'has_cdn': 1, 'is_cloud_flare': 1}
            else:
                print("has_cdn=1 from ns")
                return {'has_cdn': 1, 'is_cloud_flare': 0}
        else:
            # The following is judged by the number of records a record.
            result = get_string_from_command("dig a %s +short" % self.domain)
            find_a_record_pattern = re.findall(r"((\d{1,3}\.){3}\d{1,3})", result)
            if find_a_record_pattern:
                ip_count = 0
                for each in find_a_record_pattern:
                    ip_count += 1
                if ip_count > 1:
                    has_cdn = 1
                    return {'has_cdn': 1, 'is_cloud_flare': 0}
        return {'has_cdn': 0, 'is_cloud_flare': 0}


    def get_domain_actual_ip_from_phpinfo(self):
        # Try to get real IP from PHPINFO page
        CLIOutput().good_print("现在尝试从domain:%s可能存在的phpinfo页面获取真实ip" % self.domain)
        phpinfo_page_list = ["info.php", "phpinfo.php", "test.php", "l.php"]
        for each in phpinfo_page_list:
            url = self.http_or_https + "://" + self.domain + "/" + each
            CLIOutput().good_print("现在访问%s" % url)
            visit = get_request(url,'seleniumPhantomJS')
            code = visit['code']
            content = visit['content']
            pattern = re.compile(r"remote_addr", re.I)
            if code == 200 and re.search(pattern, content):
                print(each)
                actual_ip = re.search(r"REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+", content).group(1)
                return actual_ip
        # Return 0 means that the real IP is not obtained through the phpinfo page
        return 0


    def flush_dns(self):
        # This function is used to refresh the local DNS Cache
        # DNS Cache can make the modification hosts file effective
        CLIOutput().good_print("现在刷新系统的dns cache")
        command = "service network-manager restart && /etc/init.d/networking force-reload"
        os.system(command)
        import time
        time.sleep(3)


    def modify_hosts_file_with_ip_and_domain(self,ip):
        # This function is used to modify the hosts file
        CLIOutput().good_print("现在修改hosts文件")
        exists_domain_line = False
        with open("/etc/hosts", "r+") as f:
            file_content = f.read()
        if re.search(r"%s" % self.domain.replace(".", "\."), file_content):
            exists_domain_line = True
        if exists_domain_line == True:
            os.system("sed -ri 's/.*%s.*/%s    %s/' %s" % (self.domain.replace(".", "\."), ip, self.domain, "/etc/hosts"))
        else:
            os.system("echo %s %s >> /etc/hosts" % (ip, self.domain))


    def check_if_ip_is_actual_ip_of_domain(self,ip):
        # To modify whether the IP is the real IP corresponding to Domain
        # If yes are returned to TRUE, otherwise returns false
        # Clioutput (). Good_print ("Now to modify the hosts file and refresh the DNS method to detect whether the IP:%s is the real IP"%(IP, SELF.DOMAIN)) of Domain:%s)
        # Python will not be affected by DNS files when requesting through the REQUESTS library or Mechanicalsoup library or Selenium_Phantomjs. It will only be affected by the Hosts file to analyze DNS.
        CLIOutput().good_print("现在通过修改hosts文件的方法检测ip:%s是否是domain:%s的真实ip" % (ip,self.domain))
        os.system("cp /etc/hosts /etc/hosts.bak")
        self.modify_hosts_file_with_ip_and_domain(ip)
        # Python will not be affected by the DNS file when requesting through the Requests library or the Mechanicalsoup library or Selenium_Phantomjs. It will only be affected by the Hosts file.
        # Self.flush_dns ()
        hosts_changed_domain_title= get_request(self.http_or_https + "://%s" % self.domain,'selenium_phantom_js')['title']
        os.system("rm /etc/hosts && mv /etc/hosts.bak /etc/hosts")
        # It is necessary to judge with title here. HTML is not able to judge that it is not possible. Title is the same.
        if self.domain_title == hosts_changed_domain_title:
            CLIOutput().good_print("检测到真实ip!!!!!!",'red')
            return True
        else:
            CLIOutput().good_print("当前ip不是域名的真实ip",'yellow')
            return False


    def get_c_80_or_443_list(self,ip):
        # Get a list of open port 80 or port 443 IPs for the entire C segment of the IP
        if "not found" in get_string_from_command("masscan"):
            # There is no need for nmap scanning, and the nmap scan results are inaccurate
            os.system("apt-get install masscan")
        if self.http_or_https=="http":
            scanPort=80
            CLIOutput().good_print("现在进行%s的c段开了80端口机器的扫描" % ip)
        if self.http_or_https=="https":
            scanPort=443
            CLIOutput().good_print("现在进行%s的c段开了443端口机器的扫描" % ip)
        masscan_command = "masscan -p%d %s/24 > /tmp/masscan.out" % (scanPort,ip)
        os.system(masscan_command)
        with open("/tmp/masscan.out", "r+") as f:
            strings = f.read()
        # os.system("rm /tmp/masscan.out")
        import re
        allIP=re.findall(r"((\d{1,3}\.){3}\d{1,3})",strings)
        ipList=[]
        for each in allIP:
            ipList.append(each[0])
        print(ipList)
        return ipList


    def check_if_ip_c_machines_has_actual_ip_of_domain(self,ip):
        # Check whether the C segment of the IP address has the real IP address of the domain, return the real IP address if there is one, and return 0 if not
        CLIOutput().good_print("现在检测ip为%s的c段中有没有%s的真实ip" % (ip,self.domain))
        target_list=self.get_c_80_or_443_list(ip)
        for each_ip in target_list:
            if True == self.check_if_ip_is_actual_ip_of_domain(each_ip):
                return each_ip
        return 0


    def get_ip_from_mx_record(self):
        # Get the IP list from the MX record and try to find the real IP address from the C segment in the MX record
        print("尝试从mx记录中找和%s顶级域名相同的mx主机" % self.domain)
        import socket
        # domain.eg:www.baidu.com
        from exp10it import get_root_domain
        root_domain = get_root_domain(self.domain)
        from exp10it import get_string_from_command
        result = get_string_from_command("dig %s +short mx" % root_domain)
        sub_domains_list = re.findall(r"\d{1,} (.*\.%s)\." % root_domain.replace(".", "\."), result)
        ip_list = []
        for each in sub_domains_list:
            print(each)
            ip = socket.gethostbyname_ex(each)[2]
            if ip[0] not in ip_list:
                ip_list.append(ip[0])
        return ip_list


    def check_if_mx_c_machines_has_actual_ip_of_domain(self):
        # Check whether there is a real IP address of the domain in the C segment of the IP [or IP list] where the MX record of the domain is located", 
        # If there is a real IP, it will return the real IP, and if it does not, it will return 0
        CLIOutput().good_print("尝试从mx记录的c段中查找是否存在%s的真实ip" % self.domain)
        ip_list = self.get_ip_from_mx_record()
        if ip_list != []:
            for each_ip in ip_list:
                result = self.check_if_ip_c_machines_has_actual_ip_of_domain(each_ip)
                if result != 0:
                    return result
                else:
                    continue
        return 0


    def get_ip_value_from_online_cloudflare_interface(self):
        # Check the real IP from the online cloudflare in the real IP interface
        # If you query the real IP, return the IP value, if it is not found, return 0
        CLIOutput().good_print("现在从在线cloudflare类型cdn查询真实ip接口尝试获取真实ip")
        url = "http://www.crimeflare.com/cgi-bin/cfsearch.cgi"
        post_data = 'cfS=%s' % self.domain
        content = post_request(url, post_data)
        findIp = re.search(r"((\d{1,3}\.){3}\d{1,3})", content)
        if findIp:
            return findIp.group(1)
        return 0


    def get_actual_ip_from_domain(self):
        # Try to get the real IP behind Domain, provided that Domain has CDN
        # If you find it, return the IP, if not found to return 0
        CLIOutput().good_print("进入获取真实ip函数,认为每个domain都是有cdn的情况来处理")
        import socket
        has_cdn_value = self.domain_has_cdn()
        if has_cdn_value['has_cdn'] == 1:
            CLIOutput().good_print("检测到domain:%s的A记录不止一个,认为它有cdn" % self.domain)
            pass
        else:
            CLIOutput().good_print("Attention...!!! Domain doesn't have cdn,I will return the only one ip")
            true_ip = socket.gethostbyname_ex(self.domain)[2][0]
            return true_ip
        # Let's try to obtain real IP online through Cloudflare online inquiries online
        if has_cdn_value['is_cloud_flare'] == 1:
            ip_value = self.get_ip_value_from_online_cloudflare_interface()
            if ip_value != 0:
                return ip_value
            else:
                pass
        # The following is trying to obtain the real IP through the possible PHPINFO page
        ip_from_phpinfo = self.get_domain_actual_ip_from_phpinfo()
        if ip_from_phpinfo == 0:
            pass
        else:
            return ip_from_phpinfo
        # Let's try to get the real IP through the MX record
        result = self.check_if_mx_c_machines_has_actual_ip_of_domain()
        if result == 0:
            pass
        else:
            return result
        print("Unfortunately, %s is assumed to have a cdn, but the current capability under %s cannot get its true ip, so the current function will return 0." % self.domain)
        return 0


if __name__ == '__main__':
    import sys
    domain=sys.argv[1]
    Xcdn(domain)
