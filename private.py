#!/usr/bin/python
# coding:utf-8

import sys
import subprocess
import socket
import psutil
import json
import os
import random
import datetime
import traceback

from Crypto.PublicKey import RSA
from hashlib import sha512

device_white = ['eth0', 'eth1', 'eth2', 'eth3', 'bond0', 'bond1']

def get_system_serial_number():
    ret = {}
    cmd = "dmidecode -s system-serial-number"
    serial_number = subprocess.Popen(cmd, shell=True, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    sn = serial_number.stdout.readline().decode().replace("\n","")
    ret["serial_number"] = sn
    return ret

def get_mem_info():
    ret = {}
    with open("/proc/meminfo") as f:
        tmp = int(f.readline().split()[1])
    ret["mem"] = tmp / 1024
    return ret

def get_cpu_info():
    ret = {'cpu':'', 'num':0}
    with open('/proc/cpuinfo') as f:
        for line in f:
            tmp = line.split(":")
            key = tmp[0].strip()
            if key == "processor":
                ret['num'] += 1
            if key == "model name":
                ret['cpu'] = tmp[1].strip()
    return ret

def get_disk_info():
    cmd = """/sbin/fdisk -l|grep Disk|egrep -v 'identifier|mapper|Disk label'"""
    disk_data = subprocess.Popen(cmd, shell=True, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    patition_size = []
    for dev in disk_data.stdout.readlines():
        size = int(str(dev).strip().split(',')[1].split()[0]) / 1024 / 1024/ 1024
        patition_size.append(str(size))
    ret = {}
    ret["disk"] =  " + ".join(patition_size)
    return ret

def get_host_info():
    ret = {}
    name = socket.getfqdn(socket.gethostname())
    ret["host"] = name
    return ret

def get_net_info():
    ret = []
    a = psutil.net_if_addrs()
    b = a.get('eth0')
    for device in a:
        device_info = a[device]
        if device in device_white:
            tmp_device = {}
            for sinc in device_info:
                if sinc.family == 2:
                    tmp_device['ip'] = sinc.address
                if sinc.family == 17:
                    tmp_device['mac'] = sinc.address
            ret.append(tmp_device)
    r = {}
    r["net"] = ret
    return r

def pack():
    #a = get_mem_info()
    #b = get_cpu_info()
    #c = get_disk_info()
    #d = get_host_info()
    #e = get_net_info()
    #f = get_system_serial_number()
    #ret = {**f}
    ret = {}
    return ret

def salt(text):
    return text+"+"+str(random.random())

def expire(text, expire_date):
    return text + "+" + str(expire_date)

def produce_key_pair():
    keys = RSA.generate(bits=4096)
    file_list = ["private.pem", "public.pem"]
    for file_name in file_list:
        if os.path.exists(file_name):
            os.remove(file_name)
    file = open("private.pem", "wb")
    file.write(keys.export_key('PEM'))
    file.close()

    file = open("public.pem", "wb")
    file.write(keys.publickey().export_key('PEM'))
    file.close()

def produce_certification(hash_method, text, expire_date):
    print("producing certification...")
    try:
        file = open("private.pem",'r')
        private_key = RSA.import_key(file.read())
        file.close()
    except:
        print("ERROR: invalid private key file -> private.pem")
        exit(-1)
    d = private_key.d
    n = private_key.n
    try:
        s = salt(text)
        t = expire(s, expire_date)
        e = t.encode("utf-8")
    except:
        print("ERROR: invalid text, need str")
        exit(-1)
    # RSA sign the message
    # Hash
    if hash_method == "-sha512":
        hash = int.from_bytes(sha512(text.encode("utf-8")).digest(), byteorder='big')
    elif hash_method == "-none":
        hash = int.from_bytes(e, byteorder='big')
    signature = pow(hash, d, n)
    if os.path.exists("certification.cert"):
        os.remove("certification.cert")
    file = open("certification.cert", "wb")
    file.write(str(signature).encode("utf-8"))
    file.close()

if __name__ == "__main__":
    len = len(sys.argv)
    if len > 1:
        op = sys.argv[1] 
    else:
        print("invalid arguments")
        exit(-1)
    if op == "-k":
        print("producing key pair...")
        produce_key_pair()
        print("finish")
    elif op == "-c":
        if len == 3:
            expire_date = sys.argv[2]
            try:
                expire_date = datetime.datetime.strptime(expire_date, "%Y-%m-%d_%H:%M:%S")
                print("expire date:"+datetime.datetime.strftime(expire_date, "%Y-%m-%d_%H:%M:%S"))
            except:
                print("invalid date arugument")
                exit(-1)
            try:
                p = pack()
                j = json.dumps(p)
            except:
                print("ERROR: couldn't get full computer identification info")
                exit(-1)
            produce_certification("-none", j, expire_date)
            print("finish")
        # elif len == 4:
        #     hash_method = sys.argv[2]
        #     expire_date = sys.argv[3]
        #     try:
        #         p = pack()
        #         j = json.dumps(p)
        #     except:
        #         print("ERROR: couldn't get full computer identification info")
        #         exit(-1)
        #     if hash_method == "-sha512":
        #         produce_certification(hash_method,j)
        #         print("finish")
        #     elif hash_method == "-none":
        #         produce_certification(hash_method,j)
        #         print("finish")
        else:
            print("invalid arguments")
            exit(-1)
    else:
        print("invalid arguments")
        exit(-1)
    exit(1)
