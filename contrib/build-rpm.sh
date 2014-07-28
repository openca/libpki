#!/bin/bash

if [ -z "$1" ] ; then
	echo "Usage: $0 <archive_filename>"
	echo
	exit 0;
fi

rpmbuild -ta $1

if [ $? -eq 0 ] ; then
	echo "#### Moving RPMs to current directory..."
	mv /usr/src/redhat/RPMS/i386/*.rpm .
	mv /usr/src/redhat/SRPMS/*.rpm .
	echo "     Done."
else
	echo "#### RPM build error detected!"
	echo
	exit 1
fi

exit 0;
