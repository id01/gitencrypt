## GitEncrypt
This is a simple C program (which used to be a few simple Python3 scripts) to encrypt and compress a Git repo line by line.  
Line structure is `[seed] [data]`.  
First line is version, last line is sha256 hmac.  
Seeds are determined deterministically for each line, and nonce and key are derived from seed.  
When one line changes, is added, or deleted, that line, and only that line, changes completely. The other lines are left alone.  
This also uses the shoco/zlib compression algorithms to compress and decompress each line.  
C code for shoco was slightly modified, but cloned from [here](https://github.com/Ed-von-Schleck/shoco).  
Scrypt-Jane and Z85 modules were both cloned from their respective repos.  
Scrypt-Jane was built with the options `-DSCRYPT_CHACHA -DSCRYPT_BLAKE512`.  
Needs openssl, libdeflate, and libcov.  

## Usage
* Change the key, salt, and paths to files in extraconfig  
* Add extraconfig to your .git/config file: `cat extraconfig >> .git/config`  
* Add files to .gitattributes.  