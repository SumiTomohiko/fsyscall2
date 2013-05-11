
EXPORT_CMD=	inkscape --export-background-opacity 0.0 --export-png
ICON_WIDTH=	64
EXPORT_OPT=	--export-width ${ICON_WIDTH}

all: overview.png example1.png example2.png example3.png master_and_slave.png \
	a_local_machine_as_a_master.png a_local_machine_as_a_slave.png \
	open_file.png signal.png structure.png index.html not_supported.png \
	partially_supported.png fully_supported.png out_of_support.png

.SUFFIXES: .rst .html .svg .png

.rst.html:
	rst2html --stylesheet-path=default.css --link-stylesheet \
	--strip-comments < $< > $@

.svg.png:
	${EXPORT_CMD} $@ $<

fully_supported.png: fully_supported.svg Makefile
	${EXPORT_CMD} fully_supported.png ${EXPORT_OPT} fully_supported.svg

partially_supported.png: partially_supported.svg Makefile
	${EXPORT_CMD} partially_supported.png ${EXPORT_OPT} \
	partially_supported.svg

not_supported.png: not_supported.svg Makefile
	${EXPORT_CMD} not_supported.png ${EXPORT_OPT} not_supported.svg

out_of_support.png: out_of_support.svg Makefile
	${EXPORT_CMD} out_of_support.png ${EXPORT_OPT} out_of_support.svg

clean:
	rm -f *.html
