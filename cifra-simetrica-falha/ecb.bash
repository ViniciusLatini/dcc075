wget https://upload.wikimedia.org/wikipedia/commons/a/af/Tux.png
convert Tux.png tux.ppm

head -n 3 tux.ppm > header.txt
tail -n +4 tux.ppm > body.bin

openssl enc -aes-128-ecb -in body.bin -K $(cat key.priv) -out body.ecb.enc

cat header.txt body.ecb.enc > tux-ecb-enc.ppm