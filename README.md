# SMBCapture
Capture NTLM hashes using only Python without 3rd party tools or responder

## Usage
```
sudo python3 smb_capture.py                    # listen 0.0.0.0:445
sudo python3 smb_capture.py --port 445 --out hash.txt
sudo python3 smb_capture.py --no-downgrade     # don't attempt NTLMv1
```
