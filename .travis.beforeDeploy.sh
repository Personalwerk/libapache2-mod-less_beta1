#!/bin/bash
mkdir release-apache2.2
cp ./src/.libs/mod_less.so release-apache2.2/mod_less.so
cp ./conf/less.load release-apache2.2/less.load
cp ./conf/less.conf release-apache2.2/less.conf
zip -r release-apache2.2.zip release-apache2.2
