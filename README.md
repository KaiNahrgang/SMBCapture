# SMBCapture
Capture NTLM hashes using only Python without 3rd party tools or responder

## Usage
```
sudo python3 smb_capture.py                    # listen 0.0.0.0:445
sudo python3 smb_capture.py --port 445 --out hash.txt
sudo python3 smb_capture.py --no-downgrade     # don't attempt NTLMv1

## test_smb_capture
# Terminal 1:  
sudo python3 smb_capture.py --port 4455 --out hash.txt
# Terminal 2
python3 test_smb_capture.py --port 4455
```
