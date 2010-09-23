#!/bin/sh

echo "This script will install and configure Cafe grader."

echo "Installing required apt"

sudo apt-get update
sudo apt-get install mysql-server mysql-client ruby1.8 ruby1.8-dev rdoc1.8 \
  g++ gcc libmysql-ruby1.8 irb apache2 libmysqlclient15-dev build-essential \
  git-core rubygems rake openssl libopenssl-ruby

echo "Installing rails"

sudo gem install rails --no-ri --no-rdoc --version=2.3.8

echo "Fetching Cafe Grader from Git repositories"

echo "Fetching web interface"

mkdir cafe_grader
cd cafe_grader
git clone -q http://git.gitorious.org/cafe-grader/cafe-grader-web.git web

echo "Configuring rails app"

cp web/config/environment.rb.SAMPLE web/config/environment.rb

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

CAFE_PATH=`pwd`

cd web

echo "Please provide grader database:"
read database

echo "Please provide grader username:"
read username

echo "Please provide $username password:"
read password

echo "development:" > config/database.yml
echo "  adapter: mysql" >> config/database.yml
echo "  database: $database" >> config/database.yml 
echo "  username: $username" >> config/database.yml
echo "  password: $password" >> config/database.yml
echo "  host: localhost" >> config/database.yml
echo "" >> config/database.yml
echo "production:" >> config/database.yml
echo "  adapter: mysql" >> config/database.yml
echo "  database: $database" >> config/database.yml 
echo "  username: $username" >> config/database.yml
echo "  password: $password" >> config/database.yml
echo "  host: localhost" >> config/database.yml

echo "Object.instance_eval{remove_const :GRADER_ROOT_DIR}" >> config/environment.rb
echo "Object.instance_eval{remove_const :GRADING_RESULT_DIR}" >> config/environment.rb
echo "GRADER_ROOT_DIR = '$CAFE_PATH/judge'" >> config/environment.rb
echo "GRADING_RESULT_DIR = '$CAFE_PATH/judge/result'" >> config/environment.rb

echo "Installing required gems"

sudo rake gems:install
# to remove log file owned by root
sudo rm log/*
sudo rmdir log

echo "Running rake tasks to initialize database"

rake db:migrate
rake db:seed

echo "Intalling web interface complete..."
echo
echo "Fetching grader"

cd ..

mkdir judge
cd judge
git clone -q http://git.gitorious.org/cafe-grader/cafe-grader-judge-scripts.git scripts
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

cd ..

echo "Installing web server mongrel"

sudo gem install mongrel --no-ri --no-rdoc

echo "Now you are ready to run cafe grader...."
echo 
echo "Try:"
echo
echo "  cd web"
echo "  ./script/server"
echo
echo "and access web at http://localhost:3000/"
echo "The root username is 'root', its password is 'ioionrails'."

