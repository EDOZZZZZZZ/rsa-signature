# rsa-signature
## WARN: DO NOT SHARE `private.pem` WITH ANYONE!!!
### Support python3.6+, make sure your linux has subprocess & psutil packages
#### Demo Usage.
1. Install package pycryptodome:\
`pip install pycryptodome`  
If failure, try `python -m pip install pycryptodome`
2. Install package psutil if needed:\
`https://pypi.org/project/psutil`
3. Produce secret key pair:  
`python private.py -k`
4. Create a certification with no space extra message:  
`python private.py -c %Y-%m-%d_%H:%M:%S`
5. Verify the certification:  
`python public.py`
