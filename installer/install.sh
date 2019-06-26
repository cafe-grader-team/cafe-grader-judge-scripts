#!/bin/sh

#installation script for cafe-grader, for ubuntu 16.04

echo "This script will install and configure Cafe grader."

RUBY_VERSION=2.6.3
RUBY_GEMSET=grader

echo "Installing Ruby $RUBY_VERSION in RVM"

rvm install $RUBY_VERSION
rvm use $RUBY_VERSION@$RUBY_GEMSET

echo "Fetching Cafe Grader from Git repositories"

echo "Fetching web interface"

mkdir cafe_grader
cd cafe_grader
git clone -q git://github.com/cafe-grader-team/cafe-grader-web.git web

echo "Configuring rails app"

cp web/config/application.rb.SAMPLE web/config/application.rb
cp web/config/initializers/cafe_grader_config.rb.SAMPLE web/config/initializers/cafe_grader_config.rb

#replace UTC in application.rb with the system timezone
timezone='UTC'
if [ -f '/etc/timezone' ]; then
  timezone=\"`cat /etc/timezone`\"
else
  if [ -f '/etc/sysconfig/clock' ]; then
    timezone=`grep -e '^TIMEZONE' /etc/sysconfig/clock | grep -o -e '\".*\"'`
  fi
fi
replace="s!'UTC'!$timezone!g"
sed -i $replace web/config/application.rb

echo "At this point we will need MySQL user and database."
echo "Have you created MySQL user and database for Cafe grader? (Y/N) "
read ch

if [ "$ch" = "n" -o "$ch" = "N" ]
then
  echo "Please open another terminal and create the user and database for Cafe grader."
  echo "Don't forget to grant access to that database for the user."
  echo "Please have username, password, and database name ready before continue."
  echo 
  echo "The following are instructions:"
  echo "1. Run mysql:"
  echo
  echo "      mysql -u root -p"
  echo
  echo "   if you have just installed mysql, the root password is the one that you have just entered"
  echo "2. Create a new database, a new user, and grant access to grader database:"
  echo
  echo "      create user 'USERNAME'@'localhost' identified by 'PASSWORD';"
  echo "      create database \`DATABASENEME\`;"
  echo "      grant all on \`DATABASENAME\`.* to 'USERNAME'@'localhost';"
  echo
  echo "   Replace USERNAME, PASSWORD, and DATABASENAME accordingly."
  echo 
  echo "Hit enter when ready..."
  read dummy
fi

echo "Please provide grader database:"
read database

echo "Please provide grader username:"
read username

echo "Please provide $username password:"
read password

CAFE_PATH=`pwd`
cd web

echo "development:" > config/database.yml
echo "  adapter: mysql2" >> config/database.yml
echo "  encoding: utf8" >> config/database.yml
echo "  reconnect: false" >> config/database.yml
echo "  database: $database" >> config/database.yml 
echo "  pool: 5" >> config/database.yml
echo "  username: $username" >> config/database.yml
echo "  password: $password" >> config/database.yml
echo "  host: localhost" >> config/database.yml
echo "  socket: /var/run/mysqld/mysqld.sock" >> config/database.yml
echo "" >> config/database.yml
echo "production:" >> config/database.yml
echo "  adapter: mysql2" >> config/database.yml
echo "  encoding: utf8" >> config/database.yml
echo "  reconnect: false" >> config/database.yml
echo "  database: $database" >> config/database.yml 
echo "  pool: 5" >> config/database.yml
echo "  username: $username" >> config/database.yml
echo "  password: $password" >> config/database.yml
echo "  host: localhost" >> config/database.yml
echo "  socket: /var/run/mysqld/mysqld.sock" >> config/database.yml

echo "Object.instance_eval{remove_const :GRADER_ROOT_DIR}" >> config/initializers/cafe_grader_config.rb 
echo "Object.instance_eval{remove_const :GRADING_RESULT_DIR}" >> config/initializers/cafe_grader_config.rb
echo "GRADER_ROOT_DIR = '$CAFE_PATH/judge'" >> config/initializers/cafe_grader_config.rb
echo "GRADING_RESULT_DIR = '$CAFE_PATH/judge/result'" >> config/initializers/cafe_grader_config.rb

echo "Installing required gems"
#gem install bundler
#bundle install
bundle

echo "Running rake tasks to initialize database"

rake db:migrate
rake db:seed

echo "Running rake tasks to precompile the assets"

rake assets:precompile

echo "setup the secret file"
SECRET_A=`rake secret`
SECRET_B=`rake secret`
SECRET_C=`rake secret`
echo "development:" > config/secrets.yml
echo "  secret_key_base: '$SECRET_A'" >> config/secrets.yml
echo "test:" >> config/secrets.yml
echo "  secret_key_base: '$SECRET_B'" >> config/secrets.yml
echo "production:" >> config/secrets.yml
echo "  secret_key_base: '$SECRET_C'" >> config/secrets.yml

echo "Intalling web interface complete..."
echo
echo "Fetching grader"

cd ..

mkdir judge
cd judge
git clone -q git://github.com/cafe-grader-team/cafe-grader-judge-scripts.git scripts
mkdir raw
mkdir ev-exam
mkdir ev
mkdir result
mkdir log

echo "Configuring grader"

cp scripts/config/env_exam.rb.SAMPLE scripts/config/env_exam.rb
cp scripts/config/env_grading.rb.SAMPLE scripts/config/env_grading.rb

# create new environment.rb file
echo "RAILS_ROOT = '$CAFE_PATH/web'" > scripts/config/environment.rb
echo "GRADER_ROOT = '$CAFE_PATH/judge/scripts'" >> scripts/config/environment.rb
echo "require File.join(File.dirname(__FILE__),'../lib/boot')" >> scripts/config/environment.rb
echo "require File.dirname(__FILE__) + \"/env_#{GRADER_ENV}.rb\"" >> scripts/config/environment.rb

# compiling box
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
  gcc -std=c99 -o scripts/std-script/box scripts/std-script/box64-new.c
else
  g++ -o scripts/std-script/box scripts/std-script/box.cc
fi


cd ..

echo "Now you are ready to run cafe grader...."
echo 
echo "Try:"
echo
echo "  cd web"
echo "  rails s"
echo
echo "and access web at http://localhost:3000/"
echo "The root username is 'root', its password is 'ioionrails'."

