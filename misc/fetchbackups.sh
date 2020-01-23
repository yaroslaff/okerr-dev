#!/bin/bash

BDIR=~/alpha-backups/

/usr/bin/rsync -q -avz -e ssh okerr@alpha.okerr.com:backups/ $BDIR

