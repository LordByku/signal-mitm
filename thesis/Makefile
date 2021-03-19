.PHONY: all clean dist print

P = thesis

default : $P.pdf

$P.pdf  : $(wildcard *.tex *.bib sections/*.tex figures/*)
	latexmk -pdf -shell-escape -synctex=1 -interaction=nonstopmode $P

clean:
	$(RM) *.aux $P.bbl $P.blg $P.fdb_latexmk $P.fls $P.log $P.out $P.dvi $P.ps $P.ps.gz $P.synctex.gz $P.toc sections/*.aux texput.log
