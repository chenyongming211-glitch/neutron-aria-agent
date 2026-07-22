#!/usr/bin/env python3
"""Stdlib-only guarded fragment fixtures; shell callers own policy and cleanup."""
import argparse, base64, ipaddress, os, re, secrets, socket, struct, subprocess, sys, threading, time, urllib.request

ETH_ALL, ETH_IP, ETH_V6, ETH_VLAN = 3, 0x0800, 0x86dd, 0x8100

def csum(data):
    if len(data) & 1: data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xffff) + (total >> 16); total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def mac(value):
    parts = value.split(":")
    if len(parts) != 6 or any(not re.fullmatch("[0-9a-fA-F]{2}", part) for part in parts): raise ValueError("invalid MAC")
    return bytes(int(part, 16) for part in parts)

def udp(src, dst, family, token):
    body = token.encode(); head = struct.pack("!HHHH", 43000, 53, 8 + len(body), 0)
    if family == 4:
        pseudo = ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed + struct.pack("!BBH", 0, 17, len(head)+len(body))
    else:
        pseudo = ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + struct.pack("!I3xB", len(head)+len(body), 17)
    return head[:6] + struct.pack("!H", csum(pseudo + head + body) or 0xffff) + body

def packets(src, dst, family, token, ident):
    data, split = udp(src, dst, family, token), 16
    if len(data) <= split * 2: raise ValueError("fixture token too short")
    chunks = (data[:split], data[split:split*2], data[split*2:]); out=[]
    for index, body in enumerate(chunks):
        off = index * split
        if family == 4:
            flags = (0x2000 if index < 2 else 0) | off // 8
            head = struct.pack("!BBHHHBBH4s4s", 0x45,0,20+len(body),ident,flags,64,17,0,ipaddress.IPv4Address(src).packed,ipaddress.IPv4Address(dst).packed)
            head = head[:10] + struct.pack("!H", csum(head)) + head[12:]
        else:
            frag = struct.pack("!BBHI", 17,0,(off//8<<3) | (1 if index < 2 else 0),ident)
            head = struct.pack("!IHBB16s16s",0x60000000,len(frag)+len(body),44,64,ipaddress.IPv6Address(src).packed,ipaddress.IPv6Address(dst).packed) + frag
        out.append(head + body)
    return out

def frame(payload, src, dst, family, vlan):
    kind = ETH_IP if family == 4 else ETH_V6
    head = mac(dst) + mac(src)
    return head + (struct.pack("!HHH", ETH_VLAN, vlan, kind) if vlan else struct.pack("!H",kind)) + payload

def metrics(text):
    result={}
    for line in text.splitlines():
        if line.startswith("aria_fragment_events_total{"):
            labels=dict(re.findall(r'(\w+)="([^"]*)"',line)); key=(labels["family"],labels["event"])
            result[key]=result.get(key,0)+int(float(line.rsplit(None,1)[1]))
    return result

def fetch(url):
    with urllib.request.urlopen(url,timeout=5) as response: return metrics(response.read().decode())

def need_delta(before, after, family, events):
    for event in events:
        key=(family,event)
        if key not in before or key not in after or after[key] <= before[key]: raise RuntimeError("public fragment series did not increase: %s/%s" % key)

class Receiver(threading.Thread):
    def __init__(self,family,address,token,port=53): super().__init__(); self.family,self.address,self.token,self.port=family,address,token,port; self.value=None; self.ready=threading.Event()
    def run(self):
        with socket.socket(socket.AF_INET if self.family==4 else socket.AF_INET6,socket.SOCK_DGRAM) as sock:
            sock.settimeout(3); sock.bind((self.address,self.port) if self.family==4 else (self.address,self.port,0,0)); self.ready.set(); self.value=sock.recv(4096)

def send(iface, frames, namespace=None):
    if namespace:
        cmd=["ip","netns","exec",namespace,sys.executable,__file__,"--emit","--iface",iface]
        cmd += ["--frame="+base64.b64encode(item).decode() for item in frames]; subprocess.check_call(cmd); return
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(ETH_ALL)) as sock:
        for item in frames: sock.sendto(item,(iface,0))

def run(args):
    family=4 if args.family=="ipv4" else 6; token="aria-frag-"+secrets.token_hex(16)
    source_mac=open("/sys/class/net/%s/address" % args.iface).read().strip()
    raw=packets(args.source,args.destination,family,token,secrets.randbits(16 if family==4 else 32))
    order={"ordered":(0,1,2),"post-first-reorder":(0,2,1),"later-before-first":(1,0,2)}[args.scenario]
    before=fetch(args.metrics_url); receiver=Receiver(family,args.destination,token); receiver.start(); receiver.ready.wait(3)
    send(args.iface,[frame(raw[i],source_mac,args.destination_mac,family,args.vlan) for i in order],args.send_netns); receiver.join(3); after=fetch(args.metrics_url)
    if args.scenario=="later-before-first":
        need_delta(before,after,args.family,("first","miss"));
        if receiver.value is not None: raise RuntimeError("later-before-first delivered")
    else:
        need_delta(before,after,args.family,("first","hit"));
        if receiver.value != token.encode(): raise RuntimeError("random-token receiver did not receive fragmented UDP")
    print("fragment scenario %s complete" % args.scenario)

def self_test():
    v4=packets("192.0.2.1","192.0.2.2",4,"x"*40,7); assert csum(v4[0][:20])==0 and struct.unpack("!H",v4[1][6:8])[0]&0x1fff==2
    v6=packets("2001:db8::1","2001:db8::2",6,"x"*40,8); assert v6[0][6]==44 and v6[1][40]==17
    assert metrics('aria_fragment_events_total{family="ipv4",event="first"} 2\n')[("ipv4","first")]==2
    receiver=Receiver(4,"127.0.0.1","token",55353); receiver.start(); receiver.ready.wait(1)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock: sock.sendto(b"token",("127.0.0.1",55353))
    receiver.join(1); assert receiver.value==b"token"

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--self-test",action="store_true"); parser.add_argument("--run",action="store_true"); parser.add_argument("--emit",action="store_true"); parser.add_argument("--iface"); parser.add_argument("--frame",action="append",default=[]); parser.add_argument("--source"); parser.add_argument("--destination"); parser.add_argument("--destination-mac"); parser.add_argument("--family",choices=("ipv4","ipv6")); parser.add_argument("--vlan",type=int,default=0); parser.add_argument("--metrics-url"); parser.add_argument("--scenario",choices=("ordered","post-first-reorder","later-before-first"),default="ordered"); parser.add_argument("--send-netns")
    args=parser.parse_args()
    if args.self_test: self_test(); return
    if args.emit: send(args.iface,[base64.b64decode(item,validate=True) for item in args.frame]); return
    if not args.run or not all(getattr(args,key) for key in ("iface","source","destination","destination_mac","family","metrics_url")): parser.error("--run requires explicit interface, addresses, family, MAC, and metrics URL")
    if args.vlan and not 1 <= args.vlan <= 4094: parser.error("VLAN must be 1..4094")
    run(args)
if __name__=="__main__": main()
