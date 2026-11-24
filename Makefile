PORTNAME=	pfSense-pkg-SDWAN
PORTVERSION=	0.4.30
CATEGORIES=	net
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	allanlopesprado@users.noreply.github.com
COMMENT=	SD-WAN gateway monitoring and lab policy routing for pfSense CE
WWW=		https://github.com/allanlopesprado/pfsense-sdwan

NO_ARCH=	yes
NO_BUILD=	yes
NO_MTREE=	yes

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	@ ${MKDIR} ${WRKSRC}

do-install:
	@ ${MKDIR} ${STAGEDIR}${PREFIX}/pkg/shortcuts ${STAGEDIR}${PREFIX}/www/sdwan \
		${STAGEDIR}${PREFIX}/www/widgets/include ${STAGEDIR}${PREFIX}/www/widgets/widgets \
		${STAGEDIR}${PREFIX}/sbin ${STAGEDIR}${PREFIX}/etc/rc.d \
		${STAGEDIR}/etc/inc/priv ${STAGEDIR}${DATADIR} ${STAGEDIR}${PREFIX}/share/pfSense/menu
	${INSTALL_DATA} ${FILESDIR}/usr/local/pkg/*.inc ${FILESDIR}/usr/local/pkg/*.xml ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_DATA} ${FILESDIR}/usr/local/pkg/shortcuts/pkg_sdwan.inc ${STAGEDIR}${PREFIX}/pkg/shortcuts/
	${INSTALL_DATA} ${FILESDIR}/usr/local/www/sdwan/* ${STAGEDIR}${PREFIX}/www/sdwan/
	${INSTALL_DATA} ${FILESDIR}/usr/local/www/widgets/include/sdwan.inc ${STAGEDIR}${PREFIX}/www/widgets/include/
	${INSTALL_DATA} ${FILESDIR}/usr/local/www/widgets/widgets/sdwan.widget.php ${STAGEDIR}${PREFIX}/www/widgets/widgets/
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/sdwan.priv.inc ${STAGEDIR}/etc/inc/priv/
	${SED} 's|%%PKGVERSION%%|${PKGVERSION}|g' \
		${FILESDIR}/usr/local/sbin/sdwand.php > ${WRKDIR}/sdwand.php
	${INSTALL_SCRIPT} ${WRKDIR}/sdwand.php ${STAGEDIR}${PREFIX}/sbin/
	${INSTALL_SCRIPT} ${FILESDIR}/usr/local/etc/rc.d/sdwand.sh ${STAGEDIR}${PREFIX}/etc/rc.d/
	${SED} 's|%%PKGVERSION%%|${PKGVERSION}|g' \
		${FILESDIR}/usr/local/share/${PORTNAME}/info.xml > ${WRKDIR}/info.xml
	${INSTALL_DATA} ${WRKDIR}/info.xml ${STAGEDIR}${DATADIR}/
	${INSTALL_DATA} ${FILESDIR}/usr/local/share/pfSense/menu/sdwan.xml ${STAGEDIR}${PREFIX}/share/pfSense/menu/

.include <bsd.port.mk>
