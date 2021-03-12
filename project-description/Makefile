.PHONY: all clean dist print

P = proposal

default : $P.pdf

$P.pdf  : $(wildcard *.tex *.bib figures/*)
	latexmk -pdf -shell-escape -synctex=1 -interaction=nonstopmode $P

clean:
	$(RM) $P.log $P.aux $P.bbl $P.blg $P.out $P.dvi $P.ps $P.ps.gz texput.log
