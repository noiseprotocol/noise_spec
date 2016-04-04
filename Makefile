
default:
	pandoc noise.md -s --toc \
	        -f markdown+yaml_metadata_block \
		--template template_pandoc \
		--css=spec_markdown.css \
		-o noise.html
	pandoc noise.md -s --toc \
	        -f markdown+yaml_metadata_block \
		-o noise.pdf

