PKGNAME=argo-api-authn
SPECFILE=${PKGNAME}.spec
SHELL=bash
PKGVERSION = $(shell grep -s '^Version:' $(SPECFILE) | sed -e 's/Version: *//')
TMPDIR := $(shell mktemp -d /tmp/${PKGNAME}.XXXXXXXXXX)
GOPATH := $(shell mktemp -d /tmp/go.XXXXXXXXXX)
APPDIR := ${CURDIR}
GOFILES_NOVENDOR = $(shell go list ./... | grep -v '/vendor/' | sed -e 's/_\/usr\/src\/myapp/./g')

sources:
	mkdir -p ${TMPDIR}/${PKGNAME}-${PKGVERSION}/src/github.com/ARGOeu/argo-api-authn
	cp -rp . ${TMPDIR}/${PKGNAME}-${PKGVERSION}/src/github.com/ARGOeu/argo-api-authn
	cd ${TMPDIR} && tar czf ${PKGNAME}-${PKGVERSION}.tar.gz ${PKGNAME}-${PKGVERSION}
	mv ${TMPDIR}/${PKGNAME}-${PKGVERSION}.tar.gz .
	if [[ ${TMPDIR} == /tmp* ]]; then rm -rf ${TMPDIR} ;fi

go-build-linux-static:
	mkdir -p ${GOPATH}/src/github.com/ARGOeu/argo-api-authn
	cp -R . ${GOPATH}/src/github.com/ARGOeu/argo-api-authn
	cd ${GOPATH}/src/github.com/ARGOeu/argo-api-authn && \
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ${APPDIR}/argo-api-authn-linux-static . &&\
	chown ${hostUID} ${APPDIR}/argo-api-authn-linux-static

go-test:
	mkdir -p ${GOPATH}/src/github.com/ARGOeu/argo-api-authn
	cp -R . ${GOPATH}/src/github.com/ARGOeu/argo-api-authn
	cd ${GOPATH}/src/github.com/ARGOeu/argo-api-authn && \
	go get github.com/axw/gocov/... && \
	go get github.com/AlekSi/gocov-xml && \
	${GOPATH}/bin/gocov test ${GOFILES_NOVENDOR} | ${GOPATH}/bin/gocov-xml > ${APPDIR}/coverage.xml &&\
	chown ${hostUID} ${APPDIR}/coverage.xml

clean:
	@echo "Clean target - nothing to clean"