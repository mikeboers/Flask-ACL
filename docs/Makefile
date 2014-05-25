
.PHONY: default clean html

default: html

html:
	sphinx-build -b html . _build/html

clean:
	rm -rf _build/*

deploy:
	./deploy.sh .
