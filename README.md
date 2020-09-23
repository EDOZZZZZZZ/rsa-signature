# rsa-signature

#### Demo Usage
1. Install package pycryptodome:\
`pip install pycryptodome`  
If failure, try `python -m pip install pycryptodome`  
2. Produce secret key pair:  
`python private.py -k`
3. Create a certification with no space extra message:  
`python private.py -c noSpaceExtraMessage`
4. Verify the certification with same no space extra message:  
`python public.py noSpaceExtraMessage`
