#!/bin/sh

TEXTID=xbench
AUTH='xenon@eml.ru:123123'
MAINSRV='https://cp.okerr.com/'
SRV=`curl -s $MAINSRV/api/director/$TEXTID`

echo .. work with server: $SRV

HOST=www.google.com

for index in `seq 1 500`
do
    INAME=sslcert:$index
    # delete. just in case
    echo .. delete indicator $INAME
    curl -u $AUTH -X POST $SRV/api/delete/$TEXTID/$INAME      
    echo .. make indicator $INAME
    curl -u $AUTH -X POST $SRV/api/create/$TEXTID/$INAME  
    echo .. set checkmethod
    curl -u $AUTH --data "checkmethod=sslcert" $SRV/api/set/$TEXTID/$INAME  
    echo .. set arguments
    curl -u $AUTH --data "host=$HOST&port=443&days=20" $SRV/api/setarg/$TEXTID/$INAME  
    echo .. stop maintenance
    curl -u $AUTH --data "maintenance=1" $SRV/api/set/$TEXTID/$INAME  
    #echo .. request retest
    #curl -u $AUTH --data "retest=1" $SRV/api/set/$TEXTID/$INAME  
    echo
done

