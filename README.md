# spidproject

## Dep
```
go get github.com/crewjam/go-xmlsec
go get github.com/beevik/etree
go get github.com/globalsign/mgo
go get github.com/kidstuff/mongostore
go get github.com/gorilla/sessions
```

## Key
```
openssl genrsa -des3 -out sp.key 4096
openssl req -new -key sp.key -out sp.csr
cp sp.key sp.key.org
openssl rsa -in sp.key.org -out sp.key
openssl x509 -req -days 365 -in sp.csr -signkey sp.key -out sp.crt
openssl x509 -inform PEM -in sp.crt > sp.pem
```

## Go
```
sudo snap install go --classic
sudo apt-get install libxml2-dev libxmlsec1-dev pkg-config
```

## MondoDB
```
sudo apt install mongodb
sudo systemctl enable mongodb //Optional
sudo systemctl start mongodb //Optional
sudo systemctl status mongodb //Optional
```

## PATH

### Aggingere in ~/.profile
```
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$PATH
```

### Aggiungere in ~/.bashrc
```
export CGO_CFLAGS_ALLOW=".*"
```

## Esecuzione
```
go install ./...
PORT=5000 $GOPATH/bin/spidproject
```

## Deploy AWS EC2 Ubuntu

### Inserire in --> Instance State = Stop --> Instance Setting --> View/Change User Data -->
```
Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
cloud_final_modules:
- [scripts-user, always]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash
cd /home/ubuntu/go/src/spidproject/
/home/ubuntu/go/bin/spidproject
--//
```
