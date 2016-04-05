
default:
	pandoc noise.md -s --toc \
	        -f markdown+yaml_metadata_block+startnum+multiline_tables \
		--template template_pandoc.html \
		--css=spec_markdown.css \
		-o noise.html
	pandoc noise.md -s --toc \
	        -f markdown+yaml_metadata_block \
		--template template_pandoc.latex \
		-o noise.pdf

