# mod_less: automatic less compiling in apache2:

This apache2 module is written to compile less code inside to css files when they are requested, so the process will 
be transparent from any script using css no matter what it's language is.

# How it works, Default configuration:

when a request is sent to any css file this request will be handeled by this module. The module will look for a less file of the same name and compare the timestamps of those files. If the less file has been changed since the last request, the modules calls lessc and compiles a new version of the the css file. If the css file is recent, no recompile will take place. In both cases, the compiled css file will be sent back to the client.

example:
 1. request: http://localhost/themes/css/style.css
 2. the module will look for a http://localhost/themes/css/style.less and compare timestamps
   1. it will then eventually recompile http://localhost/themes/css/style.css from it
 3. content of the compiled http://localhost/themes/css/style.css is delivered

**Advantages:** When deploying your app from the test-system to the live-system (where you wouldn't use mod_less, would you?), the compiled css-files will be deployed, too, and all links will stay intact  
**Disadvantages:** The modules gets invoked on every css file, if it has a corresponding less-file or not. It whould not impact performance greatly, but who knows...  

# How it works, Alternative configuration:

this configuration needs to be enabled in less.conf

when a request is sent to any css file this request will just be passed to apache and *not* be handled by this module. No automatic recompilation will be triggered when accessing css files.
To enable automatic recompilation, instead point your application to the less file. Requests on less files are handled by this module and, as above, a recompilation will eventually be triggered. In any case, the compiled css file will be sent back to the client.

example:
 1. request: http://localhost/themes/css/style.less
 2. the module will look for a http://localhost/themes/css/style.css and compare timestamps
   1. it will then eventually recompile http://localhost/themes/css/style.css from it
 3. content of the compiled http://localhost/themes/css/style.css is delivered

**Advantages:** No extra code running when accessing css files  
**Disadvantages:** You need to change your application to point to the less files for automatic recompilationd (and back after deployment)  

# Dependencies: 

Apache2

	sudo apt-get install apache2

Less Css

LessCSS ist a NodeJS module, so first off all you need [NodeJS](http://nodejs.org/download/). Getting this on linux probably requires [compiling it from source](https://github.com/joyent/node/wiki/Installing-Node.js-via-package-manager).
When NodeJS is installed correctly, you can install the lessc compiler via npm, the NodeJS Package Manager:

	sudo npm install -g less


# Installation (as root):

	cp bin/mod_less.so /usr/lib/apache2/modules/
	chmod 644 /usr/lib/apache2/modules/mod_less.so

	cp bin/less.* /etc/apache2/mods-available/
	cd /etc/apache2/mods-enabled/
	ln -s ../mods-available/less.* .

	service apache2 restart
	tail -f /var/log/apache2/error.log

# Compile from source:
source can be found in /src/mod_less.c
to compile it you will need the apxs2 tool which can be found in the apache2-prefork-dev package

	sudo apt-get install apache2-prefork-dev

after installing apxs2 tool, cd to the root directory and execute Makefile

	make all
	make install

compiled file "mod_less.so" will be copied to /usr/lib/apache2/modules/mod_less.so and chmoded by make install.
you only need to add the less.load and less.conf as mentioned in the Installation section above.


# Configuration

The following Apache configuration directives are supported:

	<IfModule mod_less.c>
	LessRecompile Mtime
	LessRelativeUrls On
	LessCompress Off
	LessMapFile On
	</IfModule>

* LessRecompile - Mtime: rely on mtime. Always: always recompile. Auto: Check via dependency list.
* LessRelativeUrls - pass the --relative-urls flag to the lessc compiler
* LessCompress - pass the --compress flag to the lessc compiler
* LessMapFile - pass the --source-map and the --source-map-inline flag to the lessc compiler

# Developers:

- waleed al qadi (waleedq)  
- rewrite by MaZderMind (github@mazdermind.de).  
- bug fix / misc changes by Chris Williams ([PureForm](https://github.com/PureForm)).
- rewrite to C++ / map-file generation / auto recompile by Opeey ([Opeey](https://github.com/Opeey))

note: feel free to fork and contrib to this project or to drop us a mail
