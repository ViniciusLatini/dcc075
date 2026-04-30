openssl rand -hex 16 > iv.txt

openssl enc -aes-128-cbc -in body.bin -K $(cat key.priv) -iv $(cat iv.txt) -out body.cbc.enc

cat header.txt body.cbc.enc > tux-cbc-enc.ppm