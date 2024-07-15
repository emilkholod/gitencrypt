install:
	echo "Copy text from '.gitattibutes' to super '.gitattibutes'"
	echo "Add text from 'gitconfig' file to super '.git/config'"
	echo "Add '.gitencrypt_secrets' to '.gitignore'"
	git config core.fileMode false
	chmod +x gitconfig_*
	chmod +x base_script
