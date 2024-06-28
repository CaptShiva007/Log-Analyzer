import re, json
from datetime import datetime as dt
import Evtx.Evtx as evtx 
from geoip import geolite2
from collections import Counter
from operator import *
from difflib import SequenceMatcher
from matplotlib import pyplot as plt

def parseZeekConn(log_entry):
    log_data = re.split("\t", log_entry.rstrip())
    r = {}
    r["ts"] = dt.fromtimestamp(float(log_data[0]))
    r["uid"] = log_data[1]
    r["src_ip"] = log_data[2]
    r["src_port"] = log_data[3]
    r["dst_ip"] = log_data[4]
    r["proto"] = log_data[5]
    r["service"] = log_data[7]
    r["duration"] = log_data[8]
    r["src_bytes"] = log_data[9]
    r["dst_bytes"] = log_data[10]
    r["conn_state"] = log_data[11]
    r["local_src"] = log_data[12]
    r["local_rsp"] = log_data[13]
    r["missed_bytes"] = log_data[14]
    r["history"] = log_data[15]
    r["srk_pkts"] = log_data[16]
    r["src_ip_bytes"] = log_data[17]
    r["dst_pkts"] = log_data[18]
    r["dst_ip_bytes"] = log_data[19]
    r["tunnel_parents"] = log_data[20]
    return r

def parseZeekDNS(log_entry):
    log_data = re.split("\t", log_entry.rstrip())
    r = {}
    r["ts"] = dt.fromtimestamp(float(log_data[0]))
    r["uid"] = log_data[1]
    r["src_ip"] = log_data[2]
    r["src_port"] = log_data[3]
    r["dst_ip"] = log_data[4]
    r["dst_port"] = log_data[5]
    r["proto"] = log_data[6]
    r["trans_id"] = log_data[7]
    r["rtt"] = log_data[8]
    r["query"] = log_data[9]
    r["qclass"] = log_data[10]
    r["qclass_name"] = log_data[11]
    r["qtype"] = log_data[12]
    r["qtype_name"] = log_data[13]
    r["rcode"] = log_data[14]
    r["rcode_name"] = log_data[15]
    r["AA"] = log_data[16]
    r["TC"] = log_data[17]
    r["RD"] = log_data[18]
    r["RA"] = log_data[19]
    r["Z"] = log_data[20]
    r["answers"] = log_data[21]
    r["TTLs"] = log_data[22]
    r["rejected"] = log_data[23]
    return r

def parseZeekHTTP(log_entry):
    log_data = re.split("\t", log_entry.rstrip())
    r = {}
    r["ts"] = dt.fromtimestamp(float(log_data[0]))
    r["uid"] = log_data[1]
    r["src_ip"] = log_data[2]
    r["src_port"] = log_data[3]
    r["dst_ip"] = log_data[4]
    r["dst_port"] = log_data[5]
    r["trans_depth"] = log_data[6]
    r["method"] = log_data[7]
    r["host"] = log_data[8]
    r["uri"] = log_data[9]
    r["referrer"] = log_data[10]
    r["version"] = log_data[11]
    r["user_agent"] = log_data[12]
    r["origin"] = log_data[13]
    r["request_body_len"] = log_data[14]
    r["response_body_len"] = log_data[15]
    r["status_code"] = log_data[16]
    r["status_msg"] = log_data[17]
    r["info_code"] = log_data[18]
    r["info_msg"] = log_data[19]
    r["tags"] = log_data[20]
    r["username"] = log_data[21]
    r["password"] = log_data[22]
    r["proxied"] = log_data[23]
    r["src_fuids"] = log_data[24]
    r["src_filenames"] = log_data[25]
    r["src_mime_types"] = log_data[26]
    r["dst_fuids"] = log_data[27]
    r["dst_filenames"] = log_data[28]
    r["dst_mime_types"] = log_data[29]
    return r

def parseSMB(log_entry):
    pattern = r"^(?P<ts>[0-9]{2}:[0-9]{2}:[0-9]{2})\s:\s(?P<client_hostname>[a-zA-Z0-9\-]+)\|(?P<client_ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\|(?P<share>[a-zA-Z0-9\-]+)\|(?P<operation>[a-zA-Z]+)\|ok\|(?P<path>.*)$"

    log_data = re.search(pattern, log_entry)
    
    r = log_data.groupdict()
    r["ts"] = dt.strptime(r['ts'], "%H:%M:%S")
    if r['operation'] == 'rename':
        r['path'] = r['path'].split("|")[-1]
    return r

def parseEvtx(event):
    sys_tag = event.find("System", event.nsmap)
    event_id = sys_tag.find("EventID", event.nsmap)
    event_ts = sys_tag.find("TimeCreated", event.nsmap)
    event_data = event.find("EventData", event.nsmap)
    r = {}
    r["ts"] = event_ts.values()[0]
    r["eid"] = event_id.text
    for data in event_data.getchildren():
        r[data.attrib["Name"]] = data.text
    return r

def parseAuth(log_entry):
    log_data = re.search(
        r"^(?P<ts>\w{3}\s\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2})" + 
        r"\s(?P<host>[\w\-]+)" +
        r"\s(sshd\[\d{1,6}\]):" +
        r"\s(?P<action>Failed|Accepted) password for(\s(?P<invalid>invalid user))?" +
        r"\s(?P<user>[^\s]+)" +
        r"\s(from)" +
        r"\s(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})" +
        r".*$", log_entry)
    
    r = log_data.groupdict()
    r['ts'] = dt.strptime(r['ts'], r"%b %d %H:%M:%S")
    r['ts'] = r['ts'].replace(year=dt.utcnow().year)
    r['country'] = geolite2.lookup(r['ip']).country
    return r
