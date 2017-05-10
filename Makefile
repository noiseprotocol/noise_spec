
default: output/noise.html output/noise.pdf output/noise_book2.pdf

# Pandoc 1.17.2, Pandoc-citeproc  

output/noise.html: noise.md template_pandoc.html spec_markdown.css my.bib
	pandoc noise.md -s --toc \
	        -f markdown\
		--template template_pandoc.html \
		--css=spec_markdown.css \
		--filter pandoc-citeproc \
		-o output/noise.html

output/noise.pdf: noise.md template_pandoc.latex my.bib
	pandoc noise.md -s --toc \
	        -f markdown\
		--template template_pandoc.latex \
		--filter pandoc-citeproc \
		-o output/noise.pdf

output/noise_book2.pdf: noise_book2.md template_pandoc.latex my.bib
	pandoc noise_book2.md -s --toc \
	        -f markdown\
		--template template_pandoc.latex \
		--filter pandoc-citeproc \
		-o output/noise_book2.pdf
clean:
	rm output/noise.html output/noise.pdf output/noise_book2.pdf
