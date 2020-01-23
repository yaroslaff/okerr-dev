#!/bin/bash

CERTDIR=${CERTDIR:-/etc/okerr/ssl/}
cmd=${1:-all}

ca(){
  echo "# make ca cert in $CERTDIR"


  if [ ! -f $CERTDIR/ca.key ]
  then
	  openssl genrsa -out $CERTDIR/ca.key 2048
	else
	  echo already exists $CERTDIR/ca.key
	fi

	if [ ! -f $CERTDIR/ca.pem ]
	then
    openssl req -x509 -new -config cert-ca.ini -key $CERTDIR/ca.key -days 10000 -out $CERTDIR/ca.pem
  else
    echo already exists $CERTDIR/ca.pem
  fi
  echo
}

client(){
  CNAME=${1:-client}
  echo "# generate client cert $CNAME"

  if [ ! -f $CERTDIR/$CNAME.key ]
  then
    openssl genrsa -out $CERTDIR/$CNAME.key 2048
  else
    echo already exists $CERTDIR/$CNAME.key
  fi

  if [ ! -f $CERTDIR/$CNAME.csr ]
  then
    openssl req -new -config cert.ini -key $CERTDIR/$CNAME.key -out $CERTDIR/$CNAME.csr -subj "/CN=$CNAME"
  else
    echo alredy exists $CERTDIR/$CNAME.csr
  fi

  if [ ! -f $CERTDIR/$CNAME.crt ]
  then
    openssl x509 -req -in $CERTDIR/$CNAME.csr -CA $CERTDIR/ca.pem -CAkey $CERTDIR/ca.key -CAcreateserial -out $CERTDIR/$CNAME.crt -days 5000
  else
    echo already exist $CERTDIR/$CNAME.crt
  fi

  if [ ! -f $CERTDIR/$CNAME.pem ]
  then
    cat $CERTDIR/$CNAME.key $CERTDIR/$CNAME.crt > $CERTDIR/$CNAME.pem
  else
    echo already exists $CERTDIR/$CNAME.pem
  fi
  echo
}

echo cmd: $cmd

case $cmd in
  ca)
    ca
    ;;
  client)
    client $2
    ;;
  all)
    ca
    client $2
esac