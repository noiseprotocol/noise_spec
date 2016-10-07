
default: noise.html noise.pdf

# Pandoc 1.17.2, Pandoc-citeproc  

noise.html: noise.md template_pandoc.html spec_markdown.css my.bib
	pandoc noise.md -s --toc \
	        -f markdown+yaml_metadata_block+startnum \
		--template template_pandoc.html \
		--css=spec_markdown.css \
		--filter pandoc-citeproc \
		-o noise.html

noise.pdf: noise.md template_pandoc.latex my.bib
	pandoc noise.md -s --toc \
	        -f markdown+yaml_metadata_block+startnum \
		--template template_pandoc.latex \
		--filter pandoc-citeproc \
		-o noise.pdf

clean:
	rm noise.html noise.pdf
