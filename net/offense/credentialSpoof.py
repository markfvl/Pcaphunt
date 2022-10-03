import pyshark

def credentialSpoof(protocol, filePath):

    if(protocol == "http"):
        httpGetCred(filePath)
    elif(protocol == "ftp"):
        print("FTP credential spoofing has yet to be implemented")
    elif(protocol == "all"):
        pass
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
        print(f"Server IP : {httpCredentials['Server IP']}\nServer Port : {httpCredentials['Server Port']}\n")
        for k, v in httpCredentials.items():
            if k == "Credentials":
                for user, pwd in httpCredentials[k].items():
                    print(f"\t username = {user}, password = {pwd}")
    else:
        print("No HTTP credentials have been found")