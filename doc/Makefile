
all: index.html

.SUFFIXES: .rst .html

.rst.html:
	rst2html --stylesheet-path=default.css --link-stylesheet \
	--strip-comments < $< > $@

clean:
	rm -f *.html
