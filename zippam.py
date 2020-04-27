#!/usr/bin/python3
# EmreOvunc - BerkayIpek
# 27.04.2020

# pip3 install pandas requests xlrd xlwt

from os       import listdir
from os       import system
from os       import mkdir
from time     import sleep
from xlwt     import Workbook
from pandas   import ExcelFile
from requests import get
from datetime import datetime

date = str(datetime.now()).split(' ')[0]
dirName = date
mkdir(dirName)

try:
    for files in listdir("."):
        if files.endswith(".xlsx"):
            file = files
except:
    exit(0)

try:
    file_resultName  = "results.txt"
    error_resultName = "errors.txt"
    error_result = open(dirName + "/" + error_resultName, 'a')
except:
    system("rm -rf " + dirName)

try:
    excel = ExcelFile(file)
    sheet = excel.parse("Sheet1")
except:
    system("rm -rf " + dirName)
    exit(0)

ipList = []
for data in sheet['DestinationIP_1']:
    ip = data.strip().split('=')[1]
    ipList.append((ip, 0))

site1 = 'https://www.whois.com/whois/'
parse1 = 'registryData'

site2 = 'https://who.is/whois-ip/ip-address/'
parse2 = 'col-md-12 queryResponseBodyKey'

global result, result_, counter
result_ = ""
result  = []
counter = 1

subnetmask = {
    "8": "255.0.0.0",
    "9": "255.128.0.0",
    "10": "255.192.0.0",
    "11": "255.224.0.0",
    "12": "255.240.0.0",
    "13": "255.248.0.0",
    "14": "255.252.0.0",
    "15": "255.254.0.0",
    "16": "255.255.0.0",
    "17": "255.255.128.0",
    "18": "255.255.192.0",
    "19": "255.255.224.0",
    "20": "255.255.240.0",
    "21": "255.255.248.0",
    "22": "255.255.252.0",
    "23": "255.255.254.0",
    "24": "255.255.255.0",
    "25": "255.255.255.128",
    "26": "255.255.255.192",
    "27": "255.255.255.224",
    "28": "255.255.255.240",
    "29": "255.255.255.248",
    "30": "255.255.255.252"
}


# IP & Subnet
def Int2Bin(integer):
    binary = '.'.join([bin(int(x) + 256)[3:] for x in integer.split('.')])
    return binary


# Wild Card
def complement(number):
    if number == '0':
        number = '1'
    elif number == '.':
        pass
    else:
        number = '0'
    return number


def find_wildcard(binary_subnet):
    binary_list = list(binary_subnet)
    wildcard = ''.join(complement(binary_list[y]) for y in range(len(binary_list)))
    return wildcard


def convert_decimal(wildcard_Binary):
    binary = {}
    for x in range(4):
        binary[x] = int(wildcard_Binary.split(".")[x], 2)
    dec = ".".join(str(binary[x]) for x in range(4))
    return dec


# Network ID
def andOP(IP1, IP2):
    ID_list = {}
    for y in range(4):
        ID_list[y] = int(IP1.split(".")[y]) & int(IP2.split(".")[y])
    ID = ".".join(str(ID_list[z]) for z in range(4))
    return ID


# Broadcast IP
def orOP(IP1, IP2):
    Broadcast_list = {}
    for z in range(4):
        Broadcast_list[z] = int(IP1.split(".")[z]) | int(IP2.split(".")[z])
    broadcast = ".".join(str(Broadcast_list[c]) for c in range(4))
    return broadcast


# Max IP
def maxiIP(brdcstIP):
    maxIPs = brdcstIP.split(".")
    if int(brdcstIP.split(".")[3]) - 1 == 0:
        if int(brdcstIP.split(".")[2]) - 1 == 0:
            if int(brdcstIP.split(".")[1]) - 1 == 0:
                maxIPs[0] = int(brdcstIP.split(".")[0]) - 1
            else:
                maxIPs[1] = int(brdcstIP.split(".")[1]) - 1
        else:
            maxIPs[2] = int(brdcstIP.split(".")[2]) - 1
    else:
        maxIPs[3] = int(brdcstIP.split(".")[3]) - 1
    return ".".join(str(maxIPs[x]) for x in range(4))


# Min IP
def miniIP(ntwrkID):
    miniIPs = ntwrkID.split(".")
    if int(ntwrkID.split(".")[3]) + 1 == 256:
        if int(ntwrkID.split(".")[2]) + 1 == 256:
            if int(ntwrkID.split(".")[1]) + 1 == 256:
                miniIPs[0] = int(ntwrkID.split(".")[0]) + 1
                miniIPs[1] = 0
                miniIPs[2] = 0
                miniIPs[3] = 0
            else:
                miniIPs[1] = int(ntwrkID.split(".")[1]) + 1
                miniIPs[2] = 0
                miniIPs[3] = 0
        else:
            miniIPs[2] = int(ntwrkID.split(".")[2]) + 1
            miniIPs[3] = 0
    else:
        miniIPs[3] = int(ntwrkID.split(".")[3]) + 1
    return ".".join(str(miniIPs[x]) for x in range(4))


def web(site, parseKey, ip):
    fl = 0
    for res in result:
        if res[0] == ip:
            fl = 1
            break

    if fl == 0:
        req = get(site + str(ip))
        if req.status_code == 200:
            try:
                try:
                    try:
                        result_ = \
                        str(req.content).split(parseKey)[1].split('OrgName')[1].split('OrgId')[0].split('\\n')[0].split(
                            ':')[1].strip()
                    except:
                        try:
                            cidr = \
                            str(req.content).split(parseKey)[1].split('CIDR')[1].split('NetName')[0].split('\\n')[
                                0].split(':')[1].strip()
                            result_ = \
                            str(req.content).split(parseKey)[1].split('netname')[1].split('country')[0].split('\\n')[
                                0].split(':')[1].strip()
                        except:
                            result_ = \
                            str(req.content).split(parseKey)[1].split('org-name')[1].split('org-type')[0].split('\\n')[
                                0].split(':')[1].strip()
                except:
                    try:
                        result_ = str(req.content).split(parseKey)[1].split('NetName')[1].split('NetHandle')[0].strip()
                    except:
                        result_ = str(req.content).split(parseKey)[1].split('<pre>')[1].split('\\n')[0]
            except:
                error_result.write(str("\n" + ip))
                result_ = ""

            subnet(req, parseKey, ip, result_)

        else:
            print(req.status_code)
            error_result.write(str("\n" + ip + ":" + req.status_code))


def subnet(req, parseKey, ip, result_):
    try:
        cidr = str(req.content).split(parseKey)[1].split('CIDR')[1].split('NetName')[0].split('\\n')[0].split(':')[
            1].strip()
        netmask = str(req.content).split(parseKey)[1].split('CIDR')[1].split('NetName')[0].split('\\n')[0].split(':')[
            1].strip().split('/')[1]
    except:
        cidr = ""
        netmask = "8"

    if not len(cidr.split(',')) > 1:

        if not netmask == "8":
            try:
                netmask = subnetmask[netmask]
                IP_binary = Int2Bin(ip)
                Subnet_binary = Int2Bin(netmask)
                IP_binary = Int2Bin(ip)
                Subnet_binary = Int2Bin(netmask)
                wildcard_binary = find_wildcard(Int2Bin(netmask))
                WildCard = convert_decimal(wildcard_binary)
                networkID = andOP(ip, netmask)
                network_Binary = Int2Bin(networkID)
                broadcastIP = orOP(networkID, WildCard)
                broadcastIP_binary = Int2Bin(broadcastIP)
                maxIP = maxiIP(broadcastIP)
                maxIP_binary = Int2Bin(maxIP)
                minIP = miniIP(networkID)
                minIP_binary = Int2Bin(networkID)

                print("IP: " + ip)

                while True:
                    maxIP, minIP, result_ = searchList(maxIP, minIP, result_)
                    if maxIP == minIP:
                        break
            except:
                error_result.write(str(ip + "\n"))
                print("ERROR: " + ip)
        else:
            maxIP, minIP, result_ = searchList(ip, ip, result_)

    else:
        maxIP, minIP, result_ = searchList(ip, ip, result_)


def searchvalid(minip, result_):
    global counter
    for nb in range(0, len(ipList)):
        if ipList[nb][1] == 0:
            if ipList[nb][0] == minip:
                ipList[nb] = (ipList[nb][0], 1)
                file_result = open(dirName + "/" + file_resultName, 'a')
                file_result.write("\n" + ipList[nb][0] + ":" + result_)
                file_result.close()
                result.append((ipList[nb][0], result_))
                counter += 1


def searchIP(maxip, minip, result_):
    if maxip.split('.')[0] == minip.split('.')[0]:
        if maxip.split('.')[1] == minip.split('.')[1]:
            if maxip.split('.')[2] == minip.split('.')[2]:
                if not maxip == minip:
                    increasePart = int(minip.split('.')[3]) + 1
                    minip = minip.split('.')[0] + "." + minip.split('.')[1] + "." + minip.split('.')[2] + "." + str(
                        increasePart)
                else:
                    pass
            else:

                if minip.split('.')[3] == "255":
                    increasePart = int(minip.split('.')[2]) + 1
                    minip = minip.split('.')[0] + "." + minip.split('.')[1] + "." + str(increasePart) + ".0"
                else:
                    increasePart = int(minip.split('.')[3]) + 1
                    minip = minip.split('.')[0] + "." + minip.split('.')[1] + "." + minip.split('.')[2] + "." + str(
                        increasePart)
        else:
            if minip.split('.')[3] == "255":
                if not minip.split('.')[2] == "255":
                    increasePart = int(minip.split('.')[2]) + 1
                    minip = minip.split('.')[0] + "." + minip.split('.')[1] + "." + str(increasePart) + ".0"
                else:
                    increasePart = int(minip.split('.')[1]) + 1
                    minip = minip.split('.')[0] + "." + str(increasePart) + ".0" + ".0"
            else:
                if minip.split('.')[2] == "255":
                    increasePart = int(minip.split('.')[1]) + 1
                    minip = minip.split('.')[0] + "." + str(increasePart) + ".0" + ".0"
                else:
                    if minip.split('.')[3] == "255":
                        increasePart = int(minip.split('.')[2]) + 1
                        minip = minip.split('.')[0] + "." + minip.split('.')[1] + "." + str(increasePart) + ".0"
                    else:
                        increasePart = int(minip.split('.')[3]) + 1
                        minip = minip.split('.')[0] + "." + minip.split('.')[1] + "." + minip.split('.')[2] + "." + str(
                            increasePart)

    return maxip, minip, result_


def searchList(maxip, minip, result_):
    searchvalid(minip, result_)
    return searchIP(maxip, minip, result_)


flag = 0
for data in sheet['DestinationIP_1']:
    ip = data.strip().split('=')[1]
    if flag % 2 == 0:
        web(site1, parse1, ip)
    else:
        web(site2, parse2, ip)
    flag += 1
    sleep(3)

error_result.close()

workbook = Workbook()
sheet = workbook.add_sheet('results')

for nbr in range(0, len(result)):
        sheet.write(nbr, 0, str(result[nbr][0]))
        sheet.write(nbr, 1, str(result[nbr][1]))

workbook.save(dirName + '/results.xls')

system("rm -rf ~" + file)

exit()
