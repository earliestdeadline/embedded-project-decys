# Embedded Lab

## Part I

### Target 1: Developer password

**Relevant Artifacts:**

All artifacts for this target are located under [./TARGETS/target-1/](./TARGETS/target-1/).

- Timing attack tool: [serial_pruning.cpp](./TARGETS/target-1/serial_pruning.cpp)
- Raw timing measurements: [./tool-outputs/](./TARGETS/target-1/tool-outputs/)
  - Length-sweep results
  - Character-by-position timing measurements
- Plots:

#### Timing Results of the first 2 letters

![First_Two](./TARGETS/target-1/timing_plot_first_2.png)

#### Timing Results of the best letters at each position

![First_All](./TARGETS/target-1/timing_all_positions.png)

#### Method / Explanation

The method used for discovering the password for the dev console was a **timing attack**, this timing attack was mildly directed by the prompt of the project to first try to infer the length of the password and then advance to the inferring of individual character values, this meant at face value that the password validators probably checks the length of the submitted string and only then assesses the validity character by character.

##### Length Sweep

The length sweeping step was performed mostly by the following code:

The `runLengthSweep` function probes candidate password lengths from 1 to 20 by submitting strings made entirely of `X` over the serial interface. The assignment specifies a password made up of lowercase letters, so `X` is guaranteed to be invalid. Using the same invalid character for every candidate avoids accidentally matching a password character and affecting the timing measurements. Any character outside `a`–`z` would serve the same purpose though.

```C++
void runLengthSweep(serial::Serial& device, std::ostream& output) {
    output << "Length sweep\n";
    std::cout << "Length sweep\n";

    for (int length = 1; length <= 20; ++length) {
        const std::string candidate(length, 'X');
        Clock::duration response_time;
        if (!measureAttempt(device, candidate, response_time)) {
            return;
        }

        const auto microseconds =
            std::chrono::duration_cast<std::chrono::microseconds>(
                response_time)
                .count();
        output << length << " characters (" << candidate << "): "
               << microseconds << " us\n";
        std::cout << length << " characters (" << candidate << "): "
                  << microseconds << " us\n";
    }
}
```

##### Measuring an Attempt

The `measureAttempt` function is used for each password submission in both sweeps. Before sending anything, it calls `readUntilPrompt`, which reads and consumes incoming bytes until the stream contains `password`, indicating that the machine is ready for input. It does not explicitly clear the serial buffer; it reads through the prompt, and a timeout before the prompt is found causes the attempt to fail. After a 20 ms pause, the function starts a `std::chrono::steady_clock` timer, writes the password followed by a newline, and reads response lines until it finds `Login failure`. The measured duration therefore runs from immediately before the write through the complete failure line being read—not just to the first response byte. `steady_clock` is monotonic, and the results are converted to microseconds for output; the actual clock resolution depends on the system, and since this is executing on a linux environment there may be a few microseconds of jitter on each measurement but it didn't turn out problematic in the experiments.

```C++
bool measureAttempt(serial::Serial& device, const std::string& payload,
                    Clock::duration& elapsed) {
    std::string prompt;
    if (!readUntilPrompt(device, prompt)) {
        std::cerr << "Did not receive the password prompt. Received: "
                  << prompt << '\n';
        return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    const auto begin = Clock::now();
    device.write(payload + '\n');

    std::string response;
    do {
        response = device.readline();
        if (response.empty()) {
            std::cerr << "Timed out waiting for the login response for "
                      << payload << ".\n";
            return false;
        }
    } while (response.find("Login failure") == std::string::npos);

    elapsed = Clock::now() - begin;
    return true;
}
```

##### Inferring Positional Values

The `measureCandidate` function compares one candidate password with a fixed baseline over several repetitions. The baseline is a reference password made of `z` characters and has the expected password length. The candidate has that same length, with the already inferred prefix, one character being tested at the current position, and `a` characters filling the remaining positions. Each time measures a complete attempt, from just before sending the password until the login failure response has been read. Comparing same-length attempts helps focus on content rather than length, while the baseline provides a nearby control for general delays or timing jitter affecting both attempts.

For each repetition, the function computes `candidate time - baseline time`: a positive delta means the candidate took longer, and a negative delta means it took less time. A longer time may indicate that the candidate matched more of the password, though individual measurements can vary. The order is randomized to reduce timing-drift bias; the function records each pair in microseconds and returns the median delta, reducing the influence of noisy measurements. If either attempt fails, it stops and reports failure to its caller.

In essence the idea is that all the candidates will be compared to a baseline time measured at about the same time, and their "scores" will be derived from how much longer or how much quicker their assessment was made, this was made in an effort to address a jitter problem we were having when measuring just singular discrete timings per attempt which was leading us nowhere, this approach was "inspired" by approaches for timing attacks found online like the "Lucky Thirteen Attack

```C++
bool measureCandidate(serial::Serial& device,
                      const std::string& baseline,
                      const std::string& candidate,
                      int repetitions,
                      Clock::duration& median_delta,
                      std::ostream& raw_output,
                      std::mt19937& random_engine) {
    std::vector<Clock::duration> deltas;
    deltas.reserve(repetitions);

    for (int attempt = 0; attempt < repetitions; ++attempt) {
        Clock::duration baseline_time;
        Clock::duration candidate_time;
        Clock::duration delta;
        if (random_engine() % 2 == 0) {
            if (!measureAttempt(device, baseline, baseline_time) ||
                !measureAttempt(device, candidate, candidate_time)) {
                return false;
            }
            delta = candidate_time - baseline_time;
        } else {
            if (!measureAttempt(device, candidate, candidate_time) ||
                !measureAttempt(device, baseline, baseline_time)) {
                return false;
            }
            delta = candidate_time - baseline_time;
        }
        deltas.push_back(delta);

        const auto baseline_microseconds =
            std::chrono::duration_cast<std::chrono::microseconds>(
                baseline_time)
                .count();
        const auto candidate_microseconds =
            std::chrono::duration_cast<std::chrono::microseconds>(
                candidate_time)
                .count();
        const auto delta_microseconds =
            std::chrono::duration_cast<std::chrono::microseconds>(delta)
                .count();
        raw_output << "sample," << candidate << ',' << attempt + 1 << ','
                   << baseline_microseconds << ',' << candidate_microseconds
                   << ',' << delta_microseconds << '\n';
    }

    median_delta = median(std::move(deltas));
    return true;
}
```

**Questions:**

**1. What length did you infer?**

**Answer:** The inferred developer password length is 13 characters.

**Evidence:**

Three independent length sweeps were performed using candidates consisting of repeated X characters. The measurements exhibit a consistent timing discontinuity at a candidate length of 13 characters.

| Candidate length | Mean response time |
| ---------------: | -----------------: |
|               12 |           4340 µs |
|               13 |           5515 µs |
|               14 |           4909 µs |

The three measurements obtained for the 13-character candidate were 5512 µs, 5535 µs, and 5498 µs, resulting in a mean response time of approximately 5515 µs. The transition from 12 to 13 characters produces an increase of approximately 1175 µs. This increase was consistently reproduced across all three sweeps, indicating that it is systematic rather than attributable to measurement noise.

The anomalous measurement of 442010 µs observed for the 1-character candidate in the initial sweep was excluded from the analysis. Subsequent measurements for the same candidate were approximately 3914–3915 µs, indicating that the initial measurement was an outlier.

Based on the repeatable timing discontinuity at 13 characters, the developer password length was therefore inferred to be 13 characters.

**2. What was the timing margin of the winning character at each position?**

**Answer:** The margin is the winning character's median delta minus the second-highest candidate's median delta at that position. The available sweep results give:

| Position | Winning character |       Margin |
| -------: | :---------------: | -----------: |
|        1 |         d         |     1994 µs |
|        2 |         d         |      989 µs |
|        3 |         n         |      995 µs |
|        4 |         p         |      988 µs |
|        5 |         r         |      990 µs |
|        6 |         z         |      994 µs |
|        7 |         j         |      984 µs |
|        8 |         z         |      998 µs |
|        9 |         u         |      989 µs |
|       10 |         m         |      987 µs |
|       11 |         f         |      995 µs |
|       12 |         g         |      978 µs |
|       13 |        —        | Not recorded |

These values are calculated from the per-position candidate medians in [timing_results_11.txt](./TARGETS/target-1/tool-outputs/timing_results_11.txt). That file contains measurements only through position 12, so the winner and margin for position 13 cannot be reported from the available timing data.

**3. Which position had the *smallest* margin, and why?**

**Answer:** Position 12 had the smallest recorded margin, at 978 µs. However, the other recorded margins are very similar (984–998 µs for positions 2–11), so this small difference does not indicate a clearly harder position to infer. It is likely due to ordinary measurement variation; the data do not establish a specific reason. Position 13 is not included since its sweep results are not recorded, this because we already know that the password is 13 characters long making timing assessments is meaningless; either one of the letters works or one or more of the previous characters was deduced incorrectly.

Overall I don't know if it's because of the method we used or if other methods may have provided different margin variations but with our baselined margin based approach we couldn't observe anything significant.

### Target 2: The dumped firmware in a binary file

**Relevant Artifacts:**

- Memory dumps: [memory_0.bin](./TARGETS/target-2/memory_dumps/memory_0.bin), [memory_1.bin](./TARGETS/target-2/memory_dumps/memory_1.bin), and [memory_2.bin](./TARGETS/target-2/memory_dumps/memory_2.bin)
- Serial extraction script: [extract_memory_mapping.py](./TARGETS/target-2/extract_memory_mapping.py)
- Extracted strings: [strings_dump.txt](./TARGETS/target-2/memory_dumps/strings_dump.txt)

The saved dump hashes and sizes are:

| Memory dump | Size | SHA-256 |
| -------------------------- | -----------: | -------------------------------------------------------------------- |
| `memory_0.bin` (PROGMEM) | 69,995 bytes | `d39561e498953947074fbd8a1268ee8ac2778e853f6c320efeb815aff278a806` |
| `memory_1.bin` | 3,076 bytes | `76ce40a1c0d71a210abf72ec1435f1933eb7d2d74369896a61a4c4d6e06f87f8` |
| `memory_2.bin` | 60,734 bytes | `2f98842cb3063d024132d0da6884950b70950e00f9d79ac16f20fb60f06e2a42` |

**Explanation:**

The `extract_memory_mapping.py` script uses Python's standard library to connect to the vending machine over serial (115200 baud), submit the developer password, and select each of the three memory locations from the development menu. It captures each location's output for 10 seconds by default. From `TARGETS/target-2/`, it can be run with `python3 extract_memory_mapping.py --port /dev/ttyUSB0 --output-dir memory_dumps --dump-seconds 10`; no compilation is required. The script writes each capture as `memory_<n>.txt`; the saved captures listed above are the corresponding `.bin` artifacts.

The PROGMEM dump is `memory_0.bin`. Its SHA-256 was calculated with `sha256sum`, its byte length with `wc -c`, and the password offsets by searching the file as binary data (for example, `grep -obaF 'danprzjzumfgn' memory_dumps/memory_0.bin`). The offsets are zero-based byte positions.

**Questions:**

**1. What is the SHA-256 and byte length of your PROGMEM dump?**

**Answer:** `memory_0.bin` is 69,995 bytes. Its SHA-256 is `d39561e498953947074fbd8a1268ee8ac2778e853f6c320efeb815aff278a806`.

**2. At what offset does your developer password appear?**

**Answer:** The password appears twice in `memory_0.bin`, at byte offsets **858** and **27,881**. The latter is the occurrence in the credential data; the earlier occurrence is in the chat text.

### Target 3: Confidential strings

**Relevant Artifacts:**

All artifacts for this target are located under [/TARGETS/target-3/](./TARGETS/target-3/).

- Annotated Asset List: [asset_list.md](./TARGETS/target-3/asset_list.md)
- Full Strings Output: [full_strings_output.txt](./TARGETS/target-3/full_strings_output.txt)
  - Shell Script: [strings.sh](./TARGETS/target-3/strings.sh) (used to obtain full strings output from [binaries](./TARGETS/target-2/memory_dumps))

**Explanation:**

The first step was to run `strings` over the raw binary and read through the output for anything that looks hardcoded: credentials, keys, debug menus, protocol text. `strings.sh` runs `strings -a -n 4` against all three memory dumps and concatenates the results into full_strings_output.txt, which is the full raw output required as an artifact for this target.

Reading through that output surfaces a block of two "maintenance" accounts sitting back-to-back in `memory_0.bin`:

```c
Developer Dan
danprzjzumfgn
Admin Alan
alancywupdjmydfadoaqvshshkgucnfwvvoqhjbxrdgndhfmhryjzn
```

The developer password is already known from Target 1. The second line, `alancywupdjmydfadoaqvshshkgucnfwvvoqhjbxrdgndhfmhryjzn`, is a second, longer credential tied to an "Admin Alan" account, a second maintenance password with (presumably) higher privilege than the developer one.
To get exact byte offsets (and therefore the distance between the two passwords), each string was located in the raw binary with grep's byte-offset mode, run directly against `memory_0.bin`:

```c
grep -obUaP "danprzjzumfgn" memory_0.bin
# 862:danprzjzumfgn
# 27977:danprzjzumfgn
grep -obUaP "alancywupdjmydfadoaqvshshkgucnfwvvoqhjbxrdgndhfmhryjzn" memory_0.bin
# 28006:alancywupdjmydfadoaqvshshkgucnfwvvoqhjbxrdgndhfmhryjzn
```

Flags:

- `-o` prints only the match (not the whole line)
- `-b` prints its byte offset
- `-U` stops grep from treating the file as line-oriented text (important since this isn't a normal line-delimited file)
- `-a` forces grep to search it as text even though parts of the dump look binary
- `-P` uses Perl-compatible regex for reliability on this kind of mixed content

Beyond the two passwords, the same strings pass surfaced the other assets listed in `asset_list.md` (the RSA private key and "signature" base64 blobs, the hardcoded Signed-By: Dan string, the dev-menu text, and so on).

**Questions:**

  **1. What is the second maintenance password?**

  **Answer:** `alancywupdjmydfadoaqvshshkgucnfwvvoqhjbxrdgndhfmhryjzn`, password for the "Admin Alan" account.

  **2.  What byte offset does it sit relative to the developer password, and how long are the base64 blobs?**

  **Answer:** +29bytes. In `memory_0.bin`, `danprzjzumfgn` starts at offset 27977 and Alan’s password starts at offset 28006. The two base64 blobs found in the same strings pass are 1588 characters long (the RSA private key) and 344 characters long (the "signature").

## Part II

### Target 4: Identify the cryptographic data

**Relevant Artifacts:**
All artifacts for this target are located under [/TARGETS/target-4/](./TARGETS/target-4/).

- Extracted key (base64): [key-base64.txt](./TARGETS/target-4/key-base64.txt)
- Extracted signature (base64) :  [signature-base64.txt](./TARGETS/target-4/signature-base64.txt)
- Decoded key and signature: [key.der](./TARGETS/target-4/key.der) and [signature.bin](./TARGETS/target-4/signature.bin)
- Entropy scan script: [entropy-scan.py](./TARGETS/target-4/entropy-scan.py)
  - Script results: [entropy-scan-mem0.txt](./TARGETS/target-4/entropy-scan-mem0.txt)

**Explanation:**

Target 3 flagged two base64 blobs sitting in the chat text of `memory_0.bin`: one labeled "the key" and one labeled "the very secret signature."
For this target the first step was simply to base64-decode both into raw bytes and check their sizes, where we got that `key.der` is 1191 bytes and `signature.bin` is 256 bytes once decoded:

```c
base64 -d key-base64.txt       > key.der
base64 -d signature-base64.txt > signature.bin

wc -c key.der signature.bin
1191 key.der
 256 signature.bin
1447 total
```

Before doing anything else, the first bytes of the decoded key were inspected directly, a raw encrypted block would look like uniform noise, while structured data (a key, a certificate, etc.) encoded as ASN.1/DER starts with a recognizable tag/length header:

```c
od -A x -t x1z key.der | head -1
000000 30 82 04 a3 02 01 00 02 82 01 01 00 dc b1 60 02  >0.............`.<
```

`30` is the ASN.1 SEQUENCE tag, `82` means "long-form length, next 2 bytes," and `04 a3` is that length (1187 bytes of payload). That's immediately followed by `02 01 00` (an INTEGER of length 1, value 0) and `02 82 01 01` (an INTEGER of length 257).

This tag/length/value pattern is exactly the shape of a PKCS#1 RSAPrivateKey structure, so the next step was to parse it fully with openssl asn1parse to confirm the complete field layout:

```c
openssl asn1parse -inform DER -in key.der
    0:d=0  hl=4 l=1187 cons: SEQUENCE          
    4:d=1  hl=2 l=   1 prim: INTEGER           :00
    7:d=1  hl=4 l= 257 prim: INTEGER           :DCB16002F88EAF1F389EAAAA57968FCE30D6DA3D72E86B0F84F7D77CFB8D7B3D5D2C0014FF77654CC1F842B2FA46FB6E7E3DC7F73BC368E93CBD537B6C818C6E9B5ED3194B3D82B6F2EB4209ED1C8953FBE8B9099D7815077A3ECBD79E947AD6FBBD7118B70F58C0AEAB5DF8D8205CFE7915C6261FDC8700437FF8647729BE1261ABF30A2E40788B4E0510E23BDFE0F88F81494454CCE3C5759B8EC86F649F9429E8E8121B3F5B980169135B20A1D5EAAE7A348616F45689FCB1D3035D6FC1D6E5E6E99E0520B2262B9B90AEEAF090342381C34B021654FC2BFE998BE3672A3DD37A34BB63A5C8C0090CCC8DBC0C134424B38A617F22A33E717A54BD9290E20B
  268:d=1  hl=2 l=   3 prim: INTEGER           :010001
  273:d=1  hl=4 l= 256 prim: INTEGER           :1EF040D0F9CE6AEF7A0D0848EC117FE47C854A400E11561CED5B9F5A769B6D78FB4C55509C45BD2E470D0A30B4146A60219380AA80B6D2C8CBCA90DEFF25A42DC75B4245CBFDFA0AB2C0575833E4E9BD9BD592C72DCBAD4B0890B01BF0AFC90EC568D7E78A963CAF7A6D2CB5DB7AA1FECCB3C83D04FF71EF9006EB280E6A8C2A1DD44C5445485759D96E89A16CEE8769D6F836AA0F78F5D832B434F798C9FC0E1D7EFF7934A68A8859BD70580EE4DC81789EB44DA071D9781F0226CB13F8FF5C3BEF70A40D547AA0C767EF9BD36B486AEC6836892B3E8DB82AC9EC39C88FB092BDB0310E538DBD132479D0FCC50BFD7383DEE894BDA8CB5682A9595963D42C0D
  533:d=1  hl=3 l= 129 prim: INTEGER           :F72824A81AC38BE3EC1DB6F988ECF8961079526593E3648EAC617104A10F97500F81559B49ABFCBE55254686FCD936037779433F3D0BA9073B43A8DCF1CDB350963B92AAD85000D97044759F30B704BDC666FC86D411922ED65DD2985F963240588BFA4CBB8D5AC3C35236DF9806D803F2EA53B6A2FA77532C32B90C2CD669DD
  665:d=1  hl=3 l= 129 prim: INTEGER           :E496D535364974BC6CFF28C20CCC23AED19E4CEF295F9A75E582F637ABCAE31EE01FBD5E72BBDD9B3C73E414CA9B7CE203C55B8A6682D2D247A844396E1FEFCFE7D456DDD503DA196B5D5FEB7D56CAE38DAE7C1BB14EABCB53FB476264382528D7D843C092D55B8765493181C7C504DFC6B88D60383F0C4561F4A49A4EA0A107
  797:d=1  hl=3 l= 129 prim: INTEGER           :BE6A1C0BB34AF26CAFCD98D9990750E17461B3FC743A9D8F59F95C743F8DDE7A9CE77CC7BDB3966E20F52DE7F3C778D8A4E434CDF4BF16036F424A47A6B75EADF8807F17C6BDA459E127AD22EF0A21C9FF9FFA6FF9D46BB6500B4AA380091C3FFCB8232798DB679128DB1F519633B79B1B3C3330A351AA3AD6F36123A32BB1B5
  929:d=1  hl=3 l= 128 prim: INTEGER           :5B515A4950AF959FF497166C36FA9242B360DEF12801164E84EA857C05F81E356669A7980493C25AD292A58A1CCA72E0438B631F6E06533C47FE138B31D03658430FD3C7F8E1FA0DEF9334CF7999E3A176273F533CC8E5DE6B6555C61BAD464303BF5489A8DEED1AB0BEC5B547DE102D6950AEC1C296854B6E6F721666D4CA9F
 1060:d=1  hl=3 l= 128 prim: INTEGER           :30F50659066C7A6DBF46BDD476BF0CC8CA02217AEAD89229F9F0C488C8D8EED71ECBDE57FC9C9EF9358082D9AD4125AB9EE860F9934E1179350B57C8AEA1EFCF21F3C7BA8135A545A725A1535C77AE79538C06D08748D3BA346026B0AE8F5124C08C5B37BD7F8AC40A72C9A1C14B870AB0B5B426D9B6871C2D2899322485A66D
```

The `asn1parse` output walks the SEQUENCE as: version (0), then INTEGERs for the modulus, public exponent, private exponent, the two primes, their CRT exponents, and the coefficient. That's precisely the PKCS#1 `RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient }` schema, confirming this is a well-formed RSA private key rather than ASN.1-shaped noise.

To double-check it's actually valid (not just structurally plausible), it was loaded directly with openssl's RSA key parser:

```c
openssl rsa -inform DER -in key.der -text -noout
Private-Key: (2048 bit, 2 primes)
modulus:
    00:dc:b1:60:02:f8:8e:af:1f:38:9e:aa:aa:57:96:
    8f:ce:30:d6:da:3d:72:e8:6b:0f:84:f7:d7:7c:fb:
    8d:7b:3d:5d:2c:00:14:ff:77:65:4c:c1:f8:42:b2:
    fa:46:fb:6e:7e:3d:c7:f7:3b:c3:68:e9:3c:bd:53:
    7b:6c:81:8c:6e:9b:5e:d3:19:4b:3d:82:b6:f2:eb:
    42:09:ed:1c:89:53:fb:e8:b9:09:9d:78:15:07:7a:
    3e:cb:d7:9e:94:7a:d6:fb:bd:71:18:b7:0f:58:c0:
    ae:ab:5d:f8:d8:20:5c:fe:79:15:c6:26:1f:dc:87:
    00:43:7f:f8:64:77:29:be:12:61:ab:f3:0a:2e:40:
    78:8b:4e:05:10:e2:3b:df:e0:f8:8f:81:49:44:54:
    cc:e3:c5:75:9b:8e:c8:6f:64:9f:94:29:e8:e8:12:
    1b:3f:5b:98:01:69:13:5b:20:a1:d5:ea:ae:7a:34:
    86:16:f4:56:89:fc:b1:d3:03:5d:6f:c1:d6:e5:e6:
    e9:9e:05:20:b2:26:2b:9b:90:ae:ea:f0:90:34:23:
    81:c3:4b:02:16:54:fc:2b:fe:99:8b:e3:67:2a:3d:
    d3:7a:34:bb:63:a5:c8:c0:09:0c:cc:8d:bc:0c:13:
    44:24:b3:8a:61:7f:22:a3:3e:71:7a:54:bd:92:90:
    e2:0b
publicExponent: 65537 (0x10001)
privateExponent:
    1e:f0:40:d0:f9:ce:6a:ef:7a:0d:08:48:ec:11:7f:
    e4:7c:85:4a:40:0e:11:56:1c:ed:5b:9f:5a:76:9b:
    6d:78:fb:4c:55:50:9c:45:bd:2e:47:0d:0a:30:b4:
    14:6a:60:21:93:80:aa:80:b6:d2:c8:cb:ca:90:de:
    ff:25:a4:2d:c7:5b:42:45:cb:fd:fa:0a:b2:c0:57:
    58:33:e4:e9:bd:9b:d5:92:c7:2d:cb:ad:4b:08:90:
    b0:1b:f0:af:c9:0e:c5:68:d7:e7:8a:96:3c:af:7a:
    6d:2c:b5:db:7a:a1:fe:cc:b3:c8:3d:04:ff:71:ef:
    90:06:eb:28:0e:6a:8c:2a:1d:d4:4c:54:45:48:57:
    59:d9:6e:89:a1:6c:ee:87:69:d6:f8:36:aa:0f:78:
    f5:d8:32:b4:34:f7:98:c9:fc:0e:1d:7e:ff:79:34:
    a6:8a:88:59:bd:70:58:0e:e4:dc:81:78:9e:b4:4d:
    a0:71:d9:78:1f:02:26:cb:13:f8:ff:5c:3b:ef:70:
    a4:0d:54:7a:a0:c7:67:ef:9b:d3:6b:48:6a:ec:68:
    36:89:2b:3e:8d:b8:2a:c9:ec:39:c8:8f:b0:92:bd:
    b0:31:0e:53:8d:bd:13:24:79:d0:fc:c5:0b:fd:73:
    83:de:e8:94:bd:a8:cb:56:82:a9:59:59:63:d4:2c:
    0d
prime1:
    00:f7:28:24:a8:1a:c3:8b:e3:ec:1d:b6:f9:88:ec:
    f8:96:10:79:52:65:93:e3:64:8e:ac:61:71:04:a1:
    0f:97:50:0f:81:55:9b:49:ab:fc:be:55:25:46:86:
    fc:d9:36:03:77:79:43:3f:3d:0b:a9:07:3b:43:a8:
    dc:f1:cd:b3:50:96:3b:92:aa:d8:50:00:d9:70:44:
    75:9f:30:b7:04:bd:c6:66:fc:86:d4:11:92:2e:d6:
    5d:d2:98:5f:96:32:40:58:8b:fa:4c:bb:8d:5a:c3:
    c3:52:36:df:98:06:d8:03:f2:ea:53:b6:a2:fa:77:
    53:2c:32:b9:0c:2c:d6:69:dd
prime2:
    00:e4:96:d5:35:36:49:74:bc:6c:ff:28:c2:0c:cc:
    23:ae:d1:9e:4c:ef:29:5f:9a:75:e5:82:f6:37:ab:
    ca:e3:1e:e0:1f:bd:5e:72:bb:dd:9b:3c:73:e4:14:
    ca:9b:7c:e2:03:c5:5b:8a:66:82:d2:d2:47:a8:44:
    39:6e:1f:ef:cf:e7:d4:56:dd:d5:03:da:19:6b:5d:
    5f:eb:7d:56:ca:e3:8d:ae:7c:1b:b1:4e:ab:cb:53:
    fb:47:62:64:38:25:28:d7:d8:43:c0:92:d5:5b:87:
    65:49:31:81:c7:c5:04:df:c6:b8:8d:60:38:3f:0c:
    45:61:f4:a4:9a:4e:a0:a1:07
exponent1:
    00:be:6a:1c:0b:b3:4a:f2:6c:af:cd:98:d9:99:07:
    50:e1:74:61:b3:fc:74:3a:9d:8f:59:f9:5c:74:3f:
    8d:de:7a:9c:e7:7c:c7:bd:b3:96:6e:20:f5:2d:e7:
    f3:c7:78:d8:a4:e4:34:cd:f4:bf:16:03:6f:42:4a:
    47:a6:b7:5e:ad:f8:80:7f:17:c6:bd:a4:59:e1:27:
    ad:22:ef:0a:21:c9:ff:9f:fa:6f:f9:d4:6b:b6:50:
    0b:4a:a3:80:09:1c:3f:fc:b8:23:27:98:db:67:91:
    28:db:1f:51:96:33:b7:9b:1b:3c:33:30:a3:51:aa:
    3a:d6:f3:61:23:a3:2b:b1:b5
exponent2:
    5b:51:5a:49:50:af:95:9f:f4:97:16:6c:36:fa:92:
    42:b3:60:de:f1:28:01:16:4e:84:ea:85:7c:05:f8:
    1e:35:66:69:a7:98:04:93:c2:5a:d2:92:a5:8a:1c:
    ca:72:e0:43:8b:63:1f:6e:06:53:3c:47:fe:13:8b:
    31:d0:36:58:43:0f:d3:c7:f8:e1:fa:0d:ef:93:34:
    cf:79:99:e3:a1:76:27:3f:53:3c:c8:e5:de:6b:65:
    55:c6:1b:ad:46:43:03:bf:54:89:a8:de:ed:1a:b0:
    be:c5:b5:47:de:10:2d:69:50:ae:c1:c2:96:85:4b:
    6e:6f:72:16:66:d4:ca:9f
coefficient:
    30:f5:06:59:06:6c:7a:6d:bf:46:bd:d4:76:bf:0c:
    c8:ca:02:21:7a:ea:d8:92:29:f9:f0:c4:88:c8:d8:
    ee:d7:1e:cb:de:57:fc:9c:9e:f9:35:80:82:d9:ad:
    41:25:ab:9e:e8:60:f9:93:4e:11:79:35:0b:57:c8:
    ae:a1:ef:cf:21:f3:c7:ba:81:35:a5:45:a7:25:a1:
    53:5c:77:ae:79:53:8c:06:d0:87:48:d3:ba:34:60:
    26:b0:ae:8f:51:24:c0:8c:5b:37:bd:7f:8a:c4:0a:
    72:c9:a1:c1:4b:87:0a:b0:b5:b4:26:d9:b6:87:1c:
    2d:28:99:32:24:85:a6:6d
```

This confirms it loads as a valid `Private-Key: (2048 bit, 2 primes)` with `publicExponent: 65537 (0x10001)`, this is a genuine, usable 2048-bit RSA private key, not a decoy.

The `signature-base64.txt` blob decodes to 256 bytes, which is exactly the modulus size of the key above (2048 bits ÷ 8 = 256 bytes), consistent with it being a raw RSA signature produced by this key, rather than its own separately-encoded structure (it does not parse as ASN.1 on its own).

Finally, `entropy-scan.py` runs a sliding-window Shannon entropy calculation over `memory_0.bin` (results in `entropy-scan-mem0.txt`) and measures specific regions for comparison:

| Region | Entropy (bits/byte) |
| --- | ---: |
| Plain-English text | ~4.85 |
| Code/menu-string region (around `DEVELOPMENT MENU`) | ~5.06 |
| Base64 key text, as stored in the firmware | ~5.81 |
| Decoded raw key bytes (`key.der`) | ~7.81 |

Even while still `base64-encoded`, the key text sits visibly above ordinary code/text entropy (base64's 64-symbol alphabet caps entropy around 6 bits/byte, well above English prose or C-style strings at ~4.5–5). Once decoded to raw bytes, the key's entropy jumps to ~7.8 out of a possible 8, essentially indistinguishable from random noise, which is the strongest signal that this is genuine high-entropy cryptographic key material rather than a string, stub, or placeholder value.

**Questions:**

  **1. What is the key size?**

  **Answer:** 2048-bit RSA private key (2 primes). Confirmed directly by `Private-Key: (2048 bit, 2 primes)` line.

  **2.  Which structural (ASN.1/DER) bytes told you what it was?**

  **Answer:** `30 82 04 A3` at the start of the decoded key. `0x30` is the ASN.1 SEQUENCE tag, `0x82` signals a long-form length (next 2 bytes), and `0x04 0xA3` = 1187 is that length. It's immediately followed by `02 01 00` (an INTEGER, length 1, value 0, the RSA key's version field) and `02 82 01 01` (an INTEGER, length 257, the modulus). That tag/length/value chain matches the PKCS#1 `RSAPrivateKey` schema exactly, which is how we know it's a structured private key rather than an opaque encrypted blob.

  **3.  How many bytes is the encrypted signature?**

  **Answer:** 256 bytes (from `wc -c key.der signature.bin`), matching the 2048-bit/256-byte modulus of the key above.

  **4.  How does the key region's entropy compare to a code region?**

  **Answer:** The key region runs noticeably higher than code/text regions even while still base64-encoded (~5.8 bits/byte vs. ~5.0 for code/menu strings and ~4.85 for plain English text), and once decoded to raw bytes it jumps to ~7.8 bits/byte, close to the theoretical maximum of 8. This stands in clear contrast to any code or string region in the dump, none of which come close to that entropy, and is the key statistical fingerprint used to pick the key material out of the rest of the firmware.

### Target 5: c&c password

### Target 6: Crack the OTP generator

### Target 7: Final secret
