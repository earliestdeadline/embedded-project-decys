import serial
import time
import re

PORT = "/dev/ttyUSB0"
BAUD = 115200
CNC_PASSWORD = "cncshneqqfaesmkhngtuakyiynloylukfsesdcpfsiuctxnxmykil" # C&C password recovered from Target 5

ser = serial.Serial(PORT, BAUD, timeout=0.05)
time.sleep(2)

def send_raw(text): 
    print(f"> sending: {text!r}")
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

read_until("vending machine")
send_raw("alancywupdjmydfadoaqvshshkgucnfwvvoqhjbxrdgndhfmhryjzn\n") # Admin Alan's password
read_until("Password:")
send_raw(CNC_PASSWORD + "\n")
read_until("OTP:")

pattern = re.compile(r"was expecting (\d+)")

A, C, M = 109, 3072, 4096 # Parameters recovered from Target 6

def next_otp(x):
    return (A * x + C) % M # To determine the next value in the OTP seed [ x_(n+1) = (A * x_n + C) mod M ]

with open("otp_crack.txt", "w") as f:
    f.write("------ OTP crack transcript ------\n")

    send_raw("100\n") # Sending dummy value once to be able to determine next value (leaks x0)
    lines = read_until("OTP:")

    x0 = None
    for line in lines:
        f.write(line + "\n")
        f.flush()
        m = pattern.search(line)
        if m:
            x0 = int(m.group(1))

    if x0 is None:
        print("Seed wasn't leaked.")
    else:
        f.write(f"> Leaked seed value (x0) this boot: {x0}\n")
        predicted = next_otp(x0)
        f.write(f"> Predicted next OTP via LCG (a={A}, c={C}, m={M}): {predicted}\n")
        print(f"> Submitting predicted OTP: {predicted}")

        send_raw(f"{predicted}\n")
        final_response = read_until("Signed-By", timeout=5)
        f.write("------ Final response ------\n")
        for line in final_response:
            f.write(line + "\n")