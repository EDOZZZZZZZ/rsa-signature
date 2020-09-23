#!/usr/bin/python
# coding:utf-8

import sys
import subprocess
import socket
import psutil
import json

from Crypto.PublicKey import RSA
from hashlib import sha512

device_white = ['eth0', 'eth1', 'eth2', 'eth3', 'bond0', 'bond1']
expire_date = ""

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
    a = get_mem_info()
    b = get_cpu_info()
    c = get_disk_info()
    d = get_host_info()
    e = get_net_info()
    ret = {**a,**b,**c,**d,**e}
    ret["expire"] = expire_date
    return ret

def verify_certification():
    try:
        file = open("public.pem",'r')
        public_key = RSA.import_key(file.read())
        file.close()
    except:
        print("ERROR: invalid public key file -> public.pem")
        exit(-1)
    n = public_key.n
    e = public_key.e
    try:
        file = open("certification.cert",'r')
        signature = file.read()
        file.close()
    except:
        print("ERROR: miss signature file -> certification.cert")
        exit(-1)
    try:
        signature = int(signature)
    except:
        print("ERROR: invalid signature file -> certification.cert")
        exit(-1)
    try:
        p = pack()
        j = json.dumps(p).encode("utf-8")
    except:
        print("ERROR: couldn't get full computer identification info")
        exit(-1)
    # hash = int.from_bytes(sha512(j).digest(), byteorder='big')
    hash = int.from_bytes(j, byteorder='big')
    try:
        hashFromSignature = pow(signature, e, n)
    except:
        print("ERROR: invalid public key")
        exit(-1)
    print("cipher_msg", hashFromSignature.to_bytes(length=hashFromSignature.bit_length()//8+1, byteorder='big'))
    return hash == hashFromSignature

if __name__ == "__main__":
    expire_date = sys.argv[1]
    print("verifying...")
    print(verify_certification())