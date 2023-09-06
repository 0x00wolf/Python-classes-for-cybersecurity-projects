# Portable system class with useful functions for malware authors.
from requests import get
from requests.exceptions import RequestException
from system import System
from os import getuid, getlogin, cpu_count, system, walk
from os.path import join, expanduser


class System:
  
    def __init__(self):
        self.inet_connection = self.__check_inet_connection()
        self.pub_ip = self.__get_public_ip()
        self.os = platform.system()
        self.user = getlogin()
        self.home_dir = expanduser('~')
        self.cpu = platform.processor()
        self.cores = cpu_count()
        self.machine_arch = platform.architecture()[0]
        self.exec_type = platform.architecture()[1]
        self.machine = platform.machine()

  
    def __check_inet_connection(self):
        """Cross platform method of pinging Google 
        to check for internet connectivity."""
        try:
            google_dns = '8.8.8.8'
            response = system(f'ping -c 1 {google_dns} >/dev/null')
            if response == 0:
                return True
            else:
                return False
        except:
            return False

  
    def __get_public_ip(self):
        """A convenient API call. If internet, 
        get the current public ip. """
        api_uri = 'https://api.ipify.org'
        if self.inet_connection == True:
            try:
                ip = get(api_uri, timeout=3)
            except RequestException:
                pass
            return ip.text
        else:
            self.pub_ip = ''


    def print_attributes(self):
        for attribute, value in self.__dict__.items():
            if value == None:
                pass
            else:
                print(f'{attribute}: {value}')


    def path_crawl(self, path=None, ignore_files=None):
        """ Recursively crawl the selected path and return the results
        in a list variable. By default path_crawl() returns a list of
        all the files in './' and its subdirectories. 
        If path == 'user', path_crawl will use os.path.expanduser(~)
        to return a list of the current user's files."""
        file_paths = []
        if path == None:
            path = './'
        elif path.tolower() == 'user':
            path = expanduser('~')  
        else:
            path = path
        if ignore_files:
            for root, dirs, files in walk(path):
                for f in files:
                    if f in ignore_files:
                        pass
                    else:
                        f_path = join(root, f)
                        file_paths.append(f_path)
        else:
            for root, dirs, files in walk(path):
                for f in files:
                    f_path = join(root, f)
                    file_paths.append(f_path)
        return file_paths
    
