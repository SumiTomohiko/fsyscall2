
all: overview.png example1.png example2.png example3.png master_and_slave.png \
	a_local_machine_as_a_master.png a_local_machine_as_a_slave.png \
	index.html

.SUFFIXES: .rst .html .svg .png

.rst.html:
	rst2html --stylesheet-path=default.css --link-stylesheet \
	--strip-comments < $< > $@

.svg.png:
	inkscape --export-png $@ $<

clean:
	rm -f *.html
