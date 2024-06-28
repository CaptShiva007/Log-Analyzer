class samples:
    zeek_conn = r"1659704789.147938	CJTvUc1gwQ6ZlYWJn8	192.168.253.154	51429	104.19.134.78	443	tcp	-	-	-	-	OTH	-	-	0	R	1	40	0	0	-"
    zeek_conn2 = r"1659704789.147939	Cbi3NL1stjQb4zOs7h	192.168.253.154	51419	65.9.86.31	443	tcp	-	-	-	-	OTH	-	-	0	R	1	40	0	0	-"

    zeek_ts = "1659704882.365669"

    auth = r"Jul 28 18:02:26 sshVictim sshd[5577]: Failed password for root from 127.0.0.1 port 51106 ssh2"
    auth2 = r"Jul 28 18:48:50 sshVictim sshd[5639]: Accepted password for toor from 127.0.0.1 port 59281 ssh2"

    auth_ts = r"Jul 28 18:02:26"
    auth_ts_formatstring = r"%b %d %H:%M:%S"

    smb = r"08:31:33 : win10-charlie|192.168.55.133|RShare|unlink|ok|autorun.inf"
    smb2 = r"06:17:13 : win7-bob|192.168.55.132|RShare|rename|ok|document-Charlie-3.txt|ShareBob/document-Charlie-3.txt"
    smb_ts_formatstring = r"%H:%M:%S"

    events = {"Monday": 3, "Tuesday":8, "Wednesday":5}