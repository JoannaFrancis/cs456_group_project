#	Push-Based Heartbeat (Unidirectional Notification): The critical process autonomously emits a small datagram (a "beat") at a regular, 
# fixed period T to the monitor. The monitor maintains an expiring countdown timer or sliding window. 


import socket
import time
import json
import logging

#heartbeat interval= 1s going off crit service implementation
#timeoutWindow = 3s till flag
#i used estTime rather then specific missed beats

def monitor(host, port):

    #UDP socket
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    serverSocket.bind((host, port))
    serverSocket.settimeout(1)

    timeoutThreshold = 3
    lastBeat = None
    faultDetected = False

    print("heartbeat monitor listening: ",host, port)
    while True:

        #waiting foe incoming UDP msg
        try:
            data, addr = serverSocket.recvfrom(4096)
        
        except socket.timeout:
            #skip decoding while still doing heartbeat checks
            data = None
            
        if data is not None:    
        #decoding msg \\ added json check to avoid crash not sure if they check that
            try:
                msg = data.decode("utf-8")
                payload = json.loads(msg)
    
            except(json.JSONDecodeError):
                print("invalid format")
                payload = None

            #Check if msgPayload = "HEARTBEAT" & service = auth ticket service
            #payload check to ensure dict before we access it
            validBeat = (isinstance(payload,dict)
                        and payload.get("type") == "HEARTBEAT" 
                        and payload.get("service") == "auth-ticket-service")

            if validBeat:

                faultDetected = False #prevents repeated logging of same outage flag

                lastBeat = time.monotonic()
                print("Heartbeat recived || Sequence:",payload.get("sequence")," || Time:[",lastBeat,"]")
            else:
                print("Invalid Heartbeat")
    
        #checks estimated time since last good beat
        if lastBeat is not None:
            estTime = time.monotonic() - lastBeat
    
            if estTime >= timeoutThreshold and not faultDetected:
                faultAlert()
                faultDetected = True
    
def faultAlert():
    timeStamp = time.strftime("%H:%M:%S")
    msg = f"[{timeStamp}] ALERT: Critical service timeout"

    print(msg)
    logging.warning("Critical service timeout")
if __name__ == "__main__":

    #creates persitent logfile if not there and logs failures
    logging.basicConfig(
        filename = "Heartbeat-Faults.log",
        level= logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s"
    )

    monitor("127.0.0.1", 9999)
