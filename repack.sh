#pip3 install --target=/Users/joshanderson/code/Meraki-vWAN/.python_packages/lib/site-packages -r requirements.txt
rm *.zip
zip -r MerakiFunction.zip . -x 'venv/*' -x '.idea/*' -x '.git/*' -x 'requirements.txt'
zip -r MerakiFunction.zip . -x 'venv/*' -x '.idea/*' -x '.git/*' -x 'requests'
#zip -r MerakiFunction.zip . -x 'venv/*' -x '.idea/*' -x '.git/*' -x '.python_packages/*'
git add MerakiFunction.zip
git commit -m "repack"