
default:
	Markdown.pl noise.md > noise.html
	pandoc noise.md -s --toc \
	        -f markdown+yaml_metadata_block \
		--template template_pandoc \
		-o noise_pandoc.html

