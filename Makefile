PORTNAME=	pfSense-pkg-SDWAN
PORTVERSION=	0.1.1
CATEGORIES=	net
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	allanlopesprado@users.noreply.github.com
COMMENT=	SD-WAN gateway monitoring and policy evaluation for pfSense CE
WWW=		https://github.com/allanlopesprado/pfsense-sdwan

NO_ARCH=	yes
NO_BUILD=	yes
NO_MTREE=	yes

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	@ ${MKDIR} ${WRKSRC}

do-install:
	@ ${MKDIR} ${STAGEDIR}${PREFIX}/pkg ${STAGEDIR}${PREFIX}/www/sdwan \
		${STAGEDIR}${PREFIX}/sbin ${STAGEDIR}${PREFIX}/etc/rc.d \
		${STAGEDIR}/etc/inc/priv ${STAGEDIR}${DATADIR}
	${INSTALL_DATA} ${FILESDIR}/usr/local/pkg/* ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_DATA} ${FILESDIR}/usr/local/www/sdwan/* ${STAGEDIR}${PREFIX}/www/sdwan/
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/sdwan.priv.inc ${STAGEDIR}/etc/inc/priv/
	${INSTALL_SCRIPT} ${FILESDIR}/usr/local/sbin/sdwand.php ${STAGEDIR}${PREFIX}/sbin/
	${INSTALL_SCRIPT} ${FILESDIR}/usr/local/etc/rc.d/sdwand.sh ${STAGEDIR}${PREFIX}/etc/rc.d/
	${SED} 's|%%PKGVERSION%%|${PKGVERSION}|g' \
		${FILESDIR}/usr/local/share/${PORTNAME}/info.xml > ${WRKDIR}/info.xml
	${INSTALL_DATA} ${WRKDIR}/info.xml ${STAGEDIR}${DATADIR}/

.include <bsd.port.mk>
