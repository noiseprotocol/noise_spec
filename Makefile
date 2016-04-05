
default: noise.html noise.pdf

noise.html: noise.md template_pandoc.html spec_markdown.css
	pandoc noise.md -s --toc \
	        -f markdown+yaml_metadata_block+startnum \
		--template template_pandoc.html \
		--css=spec_markdown.css \
		-o noise.html

noise.pdf: noise.md template_pandoc.latex
	pandoc noise.md -s --toc \
	        -f markdown+yaml_metadata_block+startnum \
		--template template_pandoc.latex \
		-o noise.pdf

clean:
	rm noise.html noise.pdf
