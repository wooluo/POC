#!/usr/bin/env python
# -*- coding: utf-8 -*-
#__author__ = '半块西瓜皮'
#__refer__ = https://labs.portcullis.co.uk/tools/ms08-067-check/
import socket

payload = [
    '00000045ff534d427200000000000008000000000000000000000000ffff000000000000002200024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00'.decode('hex'),
    '00000088ff534d427300000000080048000000000000000000000000ffffc42b000000000cff00000000f0020001000000000042000000000044c000804d00604006062b0601050502a0363034a00e300c060a2b06010401823702020aa22204204e544c4d5353500001000000050288a000000000000000000000000000000000556e69780053616d626100'.decode('hex'),
    '00000096ff534d427300000000080048000000000000000000000000ffffc42b010800000cff00000000f0020001000000000050000000000044c000805b00a14e304ca24a04484e544c4d5353500003000000000000004800000000000000480000000000000040000000000000004000000008000800400000000000000048000000050288a04e0055004c004c00556e69780053616d626100'.decode('hex'),
    '00000047ff534d427500000000080048000000000000000000000000ffffc42b0108000004ff000000000001001c0000'.decode('hex'),
    '0000005cff534d42a2000000001801480000000000000000000000000108c42b0108000018ff000000000800160000000000000003000000000000000000000080000000010000000100000040000000020000000009005c62726f7773657200'.decode('hex'),
    '00000092ff534d4225000000000801480000000000000000000000000108c42b0108000010000048000004e0ff0000000000000000000000004a0048004a000200260000404f005c504950455c0005000b03100000004800000001000000b810b810000000000100000000000100c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe808002b10486002000000'.decode('hex'),
    '000000beff534d4225000000000801480000000000000000000000000108c42b0108000010000074000004e0ff0000000000000000000000004a0074004a000200260000407b005c504950455c00050000031000000074000000010000000000000000002000000002000100000000000000010000000000aaaa0e000000000000000e0000005c00410041004100410041005c002e002e005c0046004200560000000500000000000000050000005c004600420056000000aaaa0100000000000000'.decode('hex'),
    ]

def setuserid(userid,data):
    return data[:32]+userid+data[34:]
def settreeid(treeid,data):
    return data[:28]+treeid+data[30:]
def setfid(fid,data):
    return data[:67]+fid+data[69:]
def assign(service, arg):
    if service == "smb":
        return True, arg
def audit(arg):
    ip,port = arg
    try:
        s = socket.socket()
        s.connect((ip,port))
        s.send(payload[0])
        s.recv(1024)
        s.send(payload[1])
        data = s.recv(1024)
        userid = data[32:34]
        s.send(setuserid(userid,payload[2]))
        s.recv(1024)
        data = setuserid(userid,payload[3])
        path = '\\\\%s\\IPC$\x00' % ip
        path = path + (26-len(path))*'\x3f'+'\x00'
        data = data + path
        s.send(data)
        data = s.recv(1024)
        tid = data[28:30]
        s.send(settreeid(tid,setuserid(userid,payload[4])))
        data = s.recv(1024)
        fid = data[42:44]
        s.send(setfid(fid,settreeid(tid,setuserid(userid,payload[5]))))
        s.recv(1024)
        s.send(setfid(fid,settreeid(tid,setuserid(userid,payload[6]))))
        data = s.recv(1024)
        if data.endswith('\x00'*4):
            security_hole('[ms08-067]Microsoft Windows Server服务RPC请求缓冲区溢出漏洞')
        s.close()
    except:
        pass

if __name__ == '__main__':
    from dummy import *
    audit(assign('smb', ('192.168.8.131',445))[1])
