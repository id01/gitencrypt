## GitEncrypt
This is a simple C program (which used to be a few simple Python3 scripts) to encrypt and compress a Git repo line by line.  
Line structure is `[seed] [data]`.  
First line is version, last line is sha256 hmac.  
Seeds are determined deterministically for each line, and nonce and key are derived from seed.  
There is a randomly generated "master seed" for each file that helps prevent key reuse - master keys for each file are derived from password and master seed.  
Master seeds are stored both inside the encrypted file and in separate files to make them work both on encrypt and decrypt (a little hackish).  
When one line changes, is added, or deleted, that line, and only that line, changes completely. The other lines are left alone.  
This also uses the shoco/zlib compression algorithms to compress and decompress each line.  
C code for shoco was slightly modified, but cloned from [here](https://github.com/Ed-von-Schleck/shoco).  
Scrypt-Jane and Z85 modules were both cloned from their respective repos.  
Scrypt-Jane was built with the options `-DSCRYPT_CHACHA -DSCRYPT_BLAKE512`.  
Needs openssl, libdeflate, and libcov.  
NOTE: Do not delete the .salt files! They are important!! Every time you delete them the salt will be regenerated, which means a much larger git repo!

## Usage
* Change the password and paths to files in extraconfig  
* Add extraconfig to your .git/config file: `cat extraconfig >> .git/config`  
* Add files to .gitattributes, eg: `echo '*.c filter=gitencrypt' >> .gitattributes` to encrypt all C files  
* Add `*.salt` to .gitignore.  
