#!/usr/bin/env ruby

def config
  Grader::Configuration.get_instance
end

def display_manual
  puts <<USAGE
load_testcases
using: load_testcases [problem_name ...]
  problem_name    are list of "short name" of the problems

  options:
    --dry-run     do nothing, just simulate the run
    --all         import all problem. This might take several minutes

USAGE
end

def process_options_and_stop_file

  # Process 'help' option
  if (ARGV.length==1) and (/help/.match(ARGV[0]))
    display_manual
    exit(0)
  end

  #default options
  options = {
    :dry_run => false,
  }

  options[:dry_run] = (ARGV.delete('--dry') != nil)
  options[:all] = (ARGV.delete('--all') != nil)

  return options
end

def process_problem(prob,dry_run = false)
  prob.testcases.destroy_all
  testcases_root = File.expand_path(GRADER_ROOT+"/../ev/#{prob.name}/test_cases/")
  num = 1
  puts "Processing problem #{prob.name}"
  loop do
    file_root = testcases_root + "/#{num}/"
    puts "  checking file #{file_root}"
    break unless File.exists? file_root
    input = File.read(file_root + "/input-#{num}.txt")
    answer = File.read(file_root + "/answer-#{num}.txt")
    puts "  got test case ##{num} of size #{input.size} and #{answer.size}"

    #THIS IS JUST A  PLACE HOLDER
    group = num #this is wrong!!! fix it!!
    score = 10
    #BEWARE

    prob.testcases.create(input: input,sol: answer, num: num, score:score,group: group) unless dry_run
    num += 1
  end
end

#########################################
# main program
#########################################

options = process_options_and_stop_file

# load grader environment
GRADER_ENV = 'grading'
require File.join(File.dirname(__FILE__),'config/environment')

# boot rails, to be able to use the active record
RAILS_ENV = config.rails_env
require RAILS_ROOT + '/config/environment'

if options[:all]
  Problem.all.each { |prob| process_problem(prob,options[:all]) }
else
  ARGV.each do |name|
    prob = Problem.find_by(name: name)
    process_problem(prob,options[:dry_run]) if prob
    puts "Cannot find the problem #{name}" unless prob
  end
end

