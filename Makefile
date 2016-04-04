
default:
	pandoc noise.md -s --toc \
	        -f markdown+yaml_metadata_block \
		--template template_pandoc \
		--css=markdown.css \
		-o noise.html

