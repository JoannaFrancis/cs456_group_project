#	Push-Based Heartbeat
import socket
import time
import json
import logging
import argparse
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from checkpoint import CheckpointError
from promote_standby import request_promotion
from settings import DEFAULT_STATE_DIR

HEALTH_INTERVAL = 1
#timeoutWindow = 3s till flag
HEARTBEAT_TIMEOUT = 3
#i used estTime rather then specific missed beats
RECOVERY_TIMEOUT = 5.0
START_TIMEOUT =10

def recordEvent(label, detail="", warning=False):

    msg = f"[{label}]"
    if detail:
        msg += f" {detail}"

    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)
    if warning:
        (logging.warning)(msg)
    else:
        (logging.info)(msg)

def checkHealth(url):
    #/health ready?
    try:
        with urlopen(url, timeout=.5) as response:
            if response.status != 200:
                return None
        
            body = json.load(response)
        #baseline checks of instanceID
        if(isinstance(body,dict)
            and body.get("status") == "ready" 
            and body.get("role") in ("primary", "promoted-standby") 
            and isinstance(body.get("instance_id"), str) 
            and body["instance_id"]):
            return body
    except(HTTPError, URLError, OSError, ValueError, TimeoutError):
        pass

    return None


def monitor(host, port, state_dir, health_url):

    lastBeat = None
    monitorStartTime = time.monotonic()
    currentInstance = None
    phase = "monitoring"
    lastHealthCheck = 0.0
    lastHealthAlive = None
    heartbeatDegraded = False

    #UDP socket
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    serverSocket.bind((host, port))
    serverSocket.settimeout(1)

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
    
            except(json.JSONDecodeError, UnicodeDecodeError):
                print("invalid format")
                payload = None

            #Check if msgPayload = "HEARTBEAT" & service = auth ticket service
            #payload check to ensure dict before we access it
            validBeat = (isinstance(payload,dict)
                        and payload.get("type") == "HEARTBEAT" 
                        and payload.get("service") == "auth-ticket-service"
                        and isinstance(payload.get("instance_id"),str)
                        and bool(payload["instance_id"]))

            if not validBeat:
                print("invalid heartbeat", flush=True)
            elif phase == "monitoring":
                if currentInstance is None:
                    currentInstance = payload["instance_id"]
                if payload["instance_id"] == currentInstance:
                    lastBeat = time.monotonic()
                    lastHealthAlive = None
                    
                    if heartbeatDegraded:
                        recordEvent("Heartbeat Restored", "Heartbeats resumed")
                        heartbeatDegraded = False

                    print("Heartbeat Recieved || Sequence:", payload.get("sequence"), flush=True)

        now = time.monotonic()
        #checks phase and estimated time since last good beat
        if phase == "monitoring":

            if lastBeat is None:
                if lastHealthAlive is not None:
                    referenceTime = lastHealthAlive
                else:
                    referenceTime = monitorStartTime

                #if i start monitor first it will do promotion this gives some time for that and it only flags if no heartbeat ever recieved and 10s pass
                threshold = START_TIMEOUT
            else: 
                referenceTime = lastBeat
                if lastHealthAlive is not None:
                    referenceTime= max(lastBeat,lastHealthAlive)
                    
                threshold = HEARTBEAT_TIMEOUT

            estTime = now - referenceTime

            if estTime >= threshold:
                
                health = checkHealth(health_url)

                #og service alive ye or nay // this is for better restart checks
                serviceAlive = (health is not None 
                                and (health["instance_id"] == currentInstance 
                                or ( currentInstance is None and health["role"] == "primary")))

                if serviceAlive:
                    if currentInstance is None:
                        currentInstance = health["instance_id"]
        
                    lastHealthAlive = time.monotonic()
        
                    if not heartbeatDegraded:
                        recordEvent("Heartbeat Warning", 
                                    "heartbeat missing but service responds to /health", warning = True)
                        heartbeatDegraded = True        
                else:
                    if lastBeat is None:
                        recordEvent("Startup Timeout", "No initial heartbeat recieved", warning = True)
                    else:
                        recordEvent("Crash Detected", "Critical service timeout", warning = True)

                    failoverStarted = time.monotonic()
                    promotionSignalState = promotionSignal(state_dir)

                    if promotionSignalState:
                        phase = "pending"
                    else:
                        phase = "failed"

                    lastHealthCheck = 0.0

        if phase in ("pending","failed") and now - lastHealthCheck >= HEALTH_INTERVAL:
            
            health = checkHealth(health_url)
            lastHealthCheck = now
            #picks up same service ID re responding after a drop
            if health and health["instance_id"] == currentInstance:
                recordEvent("Service Responsive", "Original service started responding again")
                lastHealthAlive = time.monotonic()
                heartbeatDegraded = True
                phase = "monitoring"
            #different service ID Restoration
            elif (health and health["instance_id"] != currentInstance and (health["role"] == "promoted-standby" or (phase == "failed" and health["role"]=="primary"))):
                recordEvent("Service Restored", 
                            f"Service ready, role ={health['role']}, " 
                            f"instance={health['instance_id']}")
                
                currentInstance = health["instance_id"]
                lastBeat = time.monotonic() #new window
                lastHealthAlive = None
                heartbeatDegraded = False
                phase = "monitoring"
                                
            #keep checks for later recovery catches without promoting
            elif phase == "pending" and now -failoverStarted >= RECOVERY_TIMEOUT:
                recordEvent("Recovery Failed", f"Secondary not ready after {RECOVERY_TIMEOUT:g}s", warning=True)
                phase = "failed" 


#2. The monitor issues a promotion signal or directly launches the failover process.
def promotionSignal(stateFlags):
    #ask the standby to prmote
    try:
        request_id = request_promotion(stateFlags)
    except (CheckpointError, OSError) as exc:
        recordEvent("Recovery Failed", f"Promotion request failed: {exc}",warning=True)
        return False

    recordEvent("Failover Triggered", f"Promotion request id={request_id}")
    return True

def logger():
    #creates persitent logfile if not there and logs failures
    logging.basicConfig(
        filename = "Heartbeat-Faults.log",
        level= logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )

if __name__ == "__main__":
    local = "127.0.0.1"

    #same state folder as standby/primary so promotion request + signing key match
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    args = parser.parse_args()

    logger()

    monitor(local, 9999, args.state_dir, f"http://{local}:8000/health")
