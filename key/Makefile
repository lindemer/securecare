keys:
	@echo Generating key pair.
	nrfutil keys generate priv.pem
	nrfutil keys display --key pk --format code priv.pem --out_file pub.c 
	nrfutil keys display --key pk --format pem priv.pem --out_file pub.pem 

