#!/bin/bash
OPATH=$(pwd)
DISTRO=$(cat /etc/os-release | head -n1 | cut -d \" -f 2 | tr -d \  )
PKGNAM=itsatrap.${DISTRO}.$(date +%Y%m%d).sh

cp itsatrap.cfg ~/.itsatrap/
cd
tar -c bin/itsatrap .itsatrap | gzip -9c > pkg.tgz
mv pkg.tgz ${OPATH}
cd $OPATH

cp bundle.sh ${PKGNAM}
base64 <pkg.tgz | sed -e 's/^/#B64#/' >>${PKGNAM}

chmod +x ${PKGNAM}
