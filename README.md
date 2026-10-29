# CS456 Authentication and Ticket Service

**Team:** Joanna Welch, Madison Wacaser, Andrew Bowman (AJ), Moze Bemelen  
**Repository:** https://github.com/JoannaFrancis/cs456_group_project

Part 1 detects service failure using UDP heartbeats. Part 2 adds ticket
checkpoints and a warm standby that can take over after the primary crashes.

Python 3.10+; no packages to install. Commands below use Windows PowerShell and
`python`. On Linux, use `python3` if needed. Run commands from the repository
folder, with all components on the same computer.

## Verify Part 2 works

Use **three terminals**, all open in the repository folder. Stop any service left
running from an earlier test.

### 1. Terminal 1: initialize and start the standby

Use the same local state folder for this test, even if the repo is in OneDrive:

```powershell
python init_state.py --state-dir "$env:LOCALAPPDATA\CS456-State"
python standby_service.py --state-dir "$env:LOCALAPPDATA\CS456-State" --ticket-ttl 300 --verbose
```

Initialize only once. If it says the key already exists, continue without changing it.

**Expected:** `[Standby Ready]`. Leave this terminal running. The standby is waiting;
it is not serving requests yet.

### 2. Terminal 2: start the primary

```powershell
python critical_service.py --state-dir "$env:LOCALAPPDATA\CS456-State" --ticket-ttl 300 --sim-leak --verbose
```

**Expected:** service startup and repeated `Checkpoint saved` messages. Leave it running.
The simulated memory leak will eventually terminate this process.

### 3. Terminal 3: create and check a ticket

```powershell
python ticket_client.py login
python ticket_client.py validate
```

**Expected:** `login 200` and `validate 200`. The ticket is saved in `demo_ticket.json`.
Wait until Terminal 2 shows another `Checkpoint saved` message after login.

### 4. Wait for the primary to crash

Watch Terminal 2. After roughly a couple of minutes, it should report simulated
memory exhaustion and exit. The exact time varies.

In Terminal 3, run:

```powershell
python ticket_client.py validate
```

**Expected:** a connection error, because the primary is down and standby has not
been promoted. The 300-second ticket lifetime gives time to finish the demo.

### 5. Terminal 3: promote the standby

```powershell
python promote_standby.py --state-dir "$env:LOCALAPPDATA\CS456-State"
```

**Expected in Terminal 1:** `Checkpoint loaded` and `[Service Restored]`.
The helper saying a request was sent is not proof of recovery; check Terminal 1.

### 6. Terminal 3: check the SAME ticket again

```powershell
python ticket_client.py validate
```

**Expected:** `validate 200` with username `alice`.
**Do not log in again.** Accepting the original ticket proves checkpoint recovery worked.
If you get 401, the ticket may have expired or was not saved before the crash;
repeat with a fresh login and wait for a checkpoint before failure.

Stop the recovered service with Ctrl+C in Terminal 1 when finished.

**Monitor integration:** these steps manually test the recovery component. AJ must
connect `monitor.py` to the promotion helper for automatic failover. See
[MONITOR_HANDOFF.md](MONITOR_HANDOFF.md). Once integrated, the monitor performs
step 5 automatically.

## Run the recovery tests

```powershell
python -m unittest discover -s tests -v
```

**Expected:** eight tests pass with `OK`. Tests cover ticket recovery, expiration,
revocation, corrupted checkpoints, and refused promotion while the primary is alive.
They passed on Linux; Windows locking support has not yet been verified on Windows.

## Part 1 authentication and heartbeat demo

Stop the Part 2 service and standby first. Initialize state as above if needed.

| Terminal | Command |
| --- | --- |
| 1 | `python monitor.py` |
| 2 | `python critical_service.py --state-dir "$env:LOCALAPPDATA\CS456-State" --verbose --sim-leak` |
| 3 | `python demo_client.py` |

**Expected client results:** login 200, validate 200, logout 200, validate 401,
incorrect-password login 401. Both 401 responses are expected rejections.

After the simulated crash, the monitor prints an alert and writes
`Heartbeat-Faults.log`. Its baseline timeout is three seconds since the last accepted
heartbeat; alerts usually appear after about three to four seconds.

## Part 1 spoofing and replay audit — Linux

Run all components on the same Linux host. Use `python3 init_state.py` once to
initialize the default local `state/` folder. Do not run standby or automatic
promotion during this baseline attack demonstration.

Compile:

```bash
g++ -std=c++17 -Wall -Wextra -o heartbeat_audit heartbeat_audit.cpp
```

With the monitor stopped, start the service in one terminal and capture a beat in another:

```bash
python3 critical_service.py --verbose
```

```bash
./heartbeat_audit capture
```

**Expected:** `captured_heartbeat.json` is saved. Stop the service with Ctrl+C.
Start the monitor and service in separate terminals:

```bash
python3 monitor.py
```

```bash
python3 critical_service.py --verbose --sim-leak
```

After the service crashes and the monitor alerts, run:

```bash
./heartbeat_audit spoof --count 6 --interval 0.75
```

Wait for another timeout, then run:

```bash
./heartbeat_audit replay --count 6 --interval 0.75
```

**Expected:** the baseline monitor accepts fake/replayed beats despite the service
being offline, then times out again after each attack stops.

## Files and behavior

| File | Purpose |
| --- | --- |
| `critical_service.py` | Authentication, heartbeats, and periodic checkpoints |
| `monitor.py` | Heartbeat monitoring; automatic promotion needs integration |
| `checkpoint.py` | Atomic checkpoint writes and HMAC verification |
| `process_lock.py` | Prevent two cooperating local processes from owning the service |
| `standby_service.py` | Wait, restore saved state, and take over on promotion |
| `init_state.py`, `settings.py` | Signing-key setup and default state path |
| `promote_standby.py` | Request takeover from the monitor or a test terminal |
| `ticket_client.py` | Keep a ticket across failover |
| `demo_client.py`, `heartbeat_audit.cpp` | Part 1 authentication and audit demos |

- HTTP: `127.0.0.1:8000`; UDP heartbeats: `127.0.0.1:9999`, once per second.
- Dummy accounts: `alice` / `alice-demo`, `bob` / `bob-demo`.
- `POST /login`, `/validate`, `/logout`; `GET /health` checks readiness.
- Checkpoints save once per second. Tickets keep their original expiration.
  Changes after the last save can be lost, including recent logouts.
- A living primary holds the ownership lock, so false promotion is refused.
  Missing, corrupted, or modified checkpoints also cause recovery refusal.
- Checkpoints and promotion requests are signed; UDP heartbeats remain unauthenticated.
  Protect the signing key. Someone who can read it can forge signed state.
- Keep generated state, keys, logs, and `demo_ticket.json` out of Git. Do not delete
  lock files or replace keys to force recovery. This implementation uses one host
  and local storage; it does not provide distributed fencing or rollback protection.
