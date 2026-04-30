openssl enc -pbkdf2 -aes-128-ecb -k minha-senha-segura -P > key_info.txt

grep "key=" key_info.txt | cut -d= -f2 > key.priv

nano cleartext.txt