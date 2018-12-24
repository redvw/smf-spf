#!/bin/sh

USER=smfs
GROUP=smfs
HOMEDIR=/etc/mail/$USER
UNAME=`uname`
PATH=$PATH:/sbin:/bin:/usr/sbin:/usr/bin

export PATH

echo -n "Creating the required user ($USER) and group ($GROUP)... "
if grep "^$GROUP:" /etc/group > /dev/null ; then
    :
else
    case $UNAME in
	*BSD)
	    pw groupadd -n $GROUP
	    ;;
	*)
	    groupadd $GROUP
    esac
fi
if grep "^$USER:" /etc/passwd > /dev/null ; then
    :
else
    case $UNAME in
	SunOS)
	    useradd -g $GROUP -d $HOMEDIR -s /usr/bin/false $USER
	    ;;
	*BSD)
	    pw useradd -c SMFS -g $GROUP -n $USER -d $HOMEDIR -s /usr/sbin/nologin
	    ;;
	*)
	    useradd -g $GROUP $USER -d $HOMEDIR -s /usr/bin/false
    esac
fi
echo "done."
