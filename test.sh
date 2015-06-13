#!/bin/bash

#first time using bash for testing!

function runtest {
if [ $cmd != $resp ]; then
	echo $msg
	echo $cmd
	echo $resp
	exit -1
fi
}

msg="error in hex to base64"
cmd=`./rypto mst h2b 00`
resp="AA=="
runtest
cmd=`./rypto mst h2b 0000`
resp="AAA="
runtest
cmd=`./rypto mst h2b 000000`
resp="AAAA"
runtest

msg="error in base64 to hex"
cmd=`./rypto mst b2h AA==`
resp="00"
runtest
cmd=`./rypto mst b2h AAA=`
resp="0000"
runtest
cmd=`./rypto mst b2h AAAA`
resp="000000"
runtest

msg="error in base64 to base64"
cmd=`./rypto mst b2b AA==`
resp="AA=="
runtest
cmd=`./rypto mst b2b AAA=`
resp="AAA="
runtest
cmd=`./rypto mst b2b AAAA`
resp="AAAA"
runtest

echo "All Good!"
