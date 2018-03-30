## GitEncrypt
These are a few simple Python3 scripts to encrypt and compress a Git repo line by line.  
Line structure is `[seed] [data]`.  
First line is version, last line is sha256 hmac.  
Seeds are determined deterministically for each line, and nonce and key are derived from seed.  
When one line changes, is added, or deleted, that line, and only that line, changes completely. The other lines are left alone.  

## Usage
* Change the key, salt, and paths to files in extraconfig  
* Add extraconfig to your .git/config file: `cat extraconfig >> .git/config`  
* Add files to .gitattributes.  