from parsers import *

def openLogFile(path):
    with open(path) as log_file:
        for log_entry in log_file:
            yield log_entry

def openEVTXFile(path):
    with evtx.Evtx(path) as log_file:
        for log_entry in log_file.records():
            yield log_entry.lxml()

def detectRunDLL32(path):
    log_file = openEVTXFile(path)
    for log_entry in log_file:
        try:
            log_data = parseEvtx(log_entry)
            if log_data["eid"] == "4688" and log_data["CommandLine"]:
                if "rundll32" in log_data["NewProcessName"] and re.search("powershell|cmd", log_data["ParentProcessName"]):
                    print(log_data["CommandLine"])
        except:
            pass

def getHTTPByUID(path):
    r = Counter()
    log_file = openLogFile(path)
    for log_entry in log_file:
        try:
            log_data = parseZeekHTTP(log_entry)
            r.update([log_data['uid']])
        except:
            pass
    return r

def detectBeacons(conn_path, http_path):
    req = getHTTPByUID(http_path)
    conn_log = openLogFile(conn_path)
    beacons = []
    for log_entry in conn_log:
        try:
            log_data = parseZeekConn(log_entry)
            if log_data['service'] == "http":
                log_data['requests'] = req[log_data['uid']]
                beacons.append(log_data)
        except:
            pass
    
    beacons.sort(key=itemgetter("requests"),reverse=True)

    header = "{:20}\t{:5}\t{:5}".format("Dst. IP","Duration", "Requests")
    print(header)
    print("-" * len(header))
    for entry in beacons[:8]:
        print("{:20}\t{:5}\t{:5}".format(entry['dst_ip'],entry['duration'],entry['requests']))

def getDNSAnomalies(path,similar_domain='globomantics.com'):
    log_file = openLogFile(path)
    domains = Counter()
    for log_entry in log_file:
        try:
            log_data = parseZeekDNS(log_entry)
            dns_query = ".".join(log_data['query'].split(".")[-2:])
            domains.update([dns_query])
        except:
            pass

    least_common = domains.most_common()[-10:]    
    domain_anomalies = []
    for domain in least_common:
        anomaly = {
            "domain":domain[0],
            "occurence":domain[1],
            "similarity":round(SequenceMatcher(None,domain[0], similar_domain).ratio()*100)
        }
        domain_anomalies.append(anomaly)
        
    domain_anomalies.sort(key=itemgetter('similarity'),reverse=True)
    return domain_anomalies

def printDNSAnomalies(path):
    domains = getDNSAnomalies(path)
    print("{:20}\t{}\t{}".format("Domain","Occurence","Similarity"))
    print("-" * 60)
    for domain in domains:
        print("{:20}\t{}\t{}".format(domain['domain'],domain['occurence'],domain['similarity']))

def printDNSQueries(path,domain):
    log_file = openLogFile(path)
    for log_entry in log_file:
        try:
            log_data = parseZeekDNS(log_entry)
            if domain in log_data['query']:
                print("{}\t{}".format(log_data['query'],log_data['answers']))
        except:
            pass

def plotBarChart(events,users):
    plt.subplot(211)
    plt.bar(range(len(events)), list(events.values()),align="center")
    plt.xticks(range(len(events)),list(events.keys()))
    plt.subplot(212)
    plt.bar(range(len(users)),list(users.values()),align="center")
    plt.xticks(range(len(users)),list(users.keys()))
    plt.show()

def getBaseTS(ts,interval):
    interval = int(60/interval)

    hours = ts.time().hour
    minutes = ts.time().minute

    base_minutes = int(minutes / interval) * interval
    return "{}:{}".format(hours,base_minutes)

def plotSMBActivity(path):
    log_file = openLogFile(path)
    users = Counter()
    events = Counter()
    for log_entry in log_file:
        try:
            log_data = parseSMB(log_entry)
            users.update([log_data['client_hostname']])
            ts = getBaseTS(log_data['ts'],4)
            events.update([ts])
        except:
            pass
    plotBarChart(events,users)
