# makefile home directory
.SILENT:
DIR=$(abspath $(dir $(realpath $(firstword $(MAKEFILE_LIST)))))
WHICH=$(realpath $(firstword $(MAKEFILE_LIST)))

all:
	make -C ${DIR} _all

_all: 
	go build -tags netgo -ldflags '-w -s' -o serve serve.go auth.go


clean:
	make -C ${DIR} _clean

_clean:
	rm -f ${DIR}/*.png
