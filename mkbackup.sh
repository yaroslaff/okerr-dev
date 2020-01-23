#!/bin/sh

BDIR=~/backup
DATESTR=`date +%Y-%m-%d`
DATEDIR=$BDIR/$DATESTR
HOSTNAME=`/bin/hostname`
ARCHFILE=$BDIR/okerr-backup-$HOSTNAME-$DATESTR.tar.gz


PYTHON=$HOME/bin/python
MANAGE="$PYTHON $HOME/okerr/manage.py"

if [ ! -d $DATEDIR ]
then
    mkdir -p $DATEDIR
fi

for pname in `$MANAGE impex --cilist -b`
do
    # echo backup $pname
    $MANAGE impex -v 0 --export --user $pname -f $DATEDIR/$pname.json
done

tar -C $BDIR -czf $ARCHFILE $DATESTR
rm -r $BDIR/$DATESTR
ln -fs $ARCHFILE $BDIR/okerr-backup-$HOSTNAME-latest.tar.gz
