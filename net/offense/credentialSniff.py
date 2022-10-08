import sys
import pyshark


def credentialSniff(protocol, filePath):

    if(protocol == "http"):
        httpGetCred(filePath)
    elif(protocol == "ftp"):
        ftpCred(filePath)
    elif(protocol == "all"):
        httpGetCred(filePath)
        ftpCred(filePath)
    else:
        print("Some error has occurred!")
        sys.exit(-2)

def httpGetCred(filePath):

    filter = "http.request.method == GET"
    filter_discarded = "http.response.code == 401" #unauthorized
        
    http_cap = pyshark.FileCapture(filePath, display_filter = filter)
    http_discard_cap = pyshark.FileCapture(filePath, display_filter = filter_discarded)

    httpCredentials = {}
    discarded = []

    for pkt in http_discard_cap:
        discarded.append(pkt.http.request_in) 
            
    for pkt in http_cap:
        payload = str(pkt.http)
        if "Credentials" in payload:
            if pkt.frame_info.number in discarded:
                continue
            index = int(payload.find("Credentials:"))
            credentialStrings = payload[index:]
            index =  credentialStrings.find(" ")
            endIndex = credentialStrings.find("\n")
            credentials = credentialStrings[index:endIndex]
            user = credentials[1:credentials.find(":")]
            pwd = credentials[credentials.find(":")+1:]
        try: 
            httpCredentials["Credentials"][user] = pwd
        except KeyError:
            httpCredentials["Server IP"] = pkt.ip.dst
            httpCredentials["Server Port"] = pkt.tcp.dstport
            httpCredentials["Credentials"] = {}
            httpCredentials["Credentials"][user] = pwd

    if(httpCredentials):    
        print(f"HTTP server IP : {httpCredentials['Server IP']}\nHTTP server Port : {httpCredentials['Server Port']}\n")
        print("HTTP CREDENTIALS:")
        for k, v in httpCredentials.items():
            if k == "Credentials":
                for user, pwd in httpCredentials[k].items():
                    print(f"\t username = {user}, password = {pwd}")
    else:
        print("No HTTP credentials have been found")
    print()

def ftpCred(filePath):

    ftp_filter = "tcp"
    ftp_cap = pyshark.FileCapture(filePath, display_filter=ftp_filter)

    datas = []
    ftpCredentials = {}
    usernames = {}
    server_not_found = True
    index = 0

    for pkt in ftp_cap:
        try:
            payload = str(pkt.tcp.payload)
            hex_user = "55:53:45:52:20"
            hex_pass = "50:41:53:53"

            if hex_user in payload:
                if(server_not_found):
                    ftpCredentials["serverIP"] = pkt.ip.dst
                    ftpCredentials["serverPort"] = pkt.tcp.dstport
                    server_not_found = False
                    datas.append(ftpCredentials)
                elif pkt.ip.dst != ftpCredentials["serverIP"]:
                    for dict in datas:
                        if pkt.ip.dst == dict["serverIP"]:
                            #server is already in list
                            continue
                        else:
                            # add server in list
                            ftpCredentials["serverIP"] = pkt.ip.dst
                            ftpCredentials["serverPort"] = pkt.tct.dstport
                            datas.append(ftpCredentials)    
                            index +=1
                #USERNAME 
                username_hex_column = payload[payload.find("20")+3 :-6]
                username_hex = "".join(n for n in username_hex_column if n.isalnum())
                user = bytes.fromhex(username_hex).decode("ascii") # got the usename in ascii
                usernames[user] = pkt.tcp.stream #save stream and username inside a dict
            #PWD
            elif hex_pass in payload:
                pwd_hex_column = payload[payload.find("53")+9 :-6]
                pwd_hex = "".join(n for n in pwd_hex_column if n.isalnum())
                pwd = bytes.fromhex(pwd_hex).decode("ascii") #got the password in ascii

                for k,v in usernames.items():
                    if v == pkt.tcp.stream:
                        try:
                            for dict in datas:
                                if pkt.ip.dst == dict["serverIP"]:
                                    dict["Credentials"][user] = pwd
                            
                        except KeyError:
                            for dict in datas:
                                if pkt.ip.dst == dict["serverIP"]:
                                    dict["Credentials"] = {}
                                    dict["Credentials"][user] = pwd
        except AttributeError:
            pass

    if(datas):  
        for dict in datas:
            print(f"FTP server IP : {dict['serverIP']}\nFTP server Port : {dict['serverPort']}\n") 
            print("FTP CREDENTIALS:")
            for k, v in dict.items():
                if k == "Credentials":
                    for user, pwd in dict[k].items():
                        print(f"\t username = {user}, password = {pwd}")
    else:
        print("No FTP credentials have been found")
    print()