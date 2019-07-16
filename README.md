# spidproject

## Dep
go get github.com/crewjam/go-xmlsec
go get github.com/beevik/etree


## PATH

### Aggingere in ~/.profile
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$PATH

### Aggiungere in ~/.bashrc
export CGO_CFLAGS_ALLOW=".*"


## Esecuzione

go install ./...
PORT=5000 $GOPATH/bin/spidproject

## Deploy AWS EC2 Ubuntu

### Inserire in --> Instance State = Stop --> Instance Setting --> View/Change User Data -->

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