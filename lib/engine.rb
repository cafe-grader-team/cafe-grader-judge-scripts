require 'fileutils'
require File.join(File.dirname(__FILE__),'dir_init')

module Grader

  #
  # A grader engine grades a submission, against anything: a test
  # data, or a user submitted test data.  It uses two helpers objects:
  # room_maker and reporter.
  #
  class Engine

    attr_writer :room_maker
    attr_writer :reporter

    def initialize(options={})
      # default options
      if not options.include? :room_maker
        options[:room_maker] = Grader::SubmissionRoomMaker.new
      end
      if not options.include? :reporter
        options[:reporter] =  Grader::SubmissionReporter.new
      end

      @config = Grader::Configuration.get_instance

      @room_maker = options[:room_maker]
      @reporter = options[:reporter]
    end

    # takes a submission, asks room_maker to produce grading directories,
    # calls grader scripts, and asks reporter to save the result
    def grade(submission)
      current_dir = FileUtils.pwd

      user = submission.user
      problem = submission.problem

      begin
        # TODO: will have to create real exception for this
        if user==nil or problem == nil
          @reporter.report_error(submission,"Grading error: problem with submission")
          raise "engine: user or problem is nil"
        end

        # TODO: this is another hack so that output only task can be judged
        if submission.language!=nil
          language = submission.language.name
          lang_ext = submission.language.ext
        else
          language = 'c'
          lang_ext = 'c'
        end

        # This is needed because older version of std-scripts/compile
        # only look for c++.
        if language == 'cpp'
          language = 'c++'
        end

        # COMMENT: should it be only source.ext?
        if problem!=nil
          source_name = "#{problem.name}.#{lang_ext}"
        else
          source_name = "source.#{lang_ext}"
        end

        grading_dir = @room_maker.produce_grading_room(submission)
        @room_maker.save_source(submission,source_name)
        problem_home = @room_maker.find_problem_home(submission)

        # puts "GRADING DIR: #{grading_dir}"
        # puts "PROBLEM DIR: #{problem_home}"

        if !FileTest.exist?(problem_home)
          puts "PROBLEM DIR: #{problem_home}"
          raise "engine: No test data."
        end

        talk "ENGINE: grading dir at #{grading_dir} is created"
        talk "ENGINE: located problem home at #{problem_home} is created"

        # copy the source script, using lock
        dinit = DirInit::Manager.new(problem_home)

        # lock the directory and copy the scripts
        dinit.setup do
          copy_log = copy_script(problem_home)
          save_copy_log(problem_home,copy_log)
          talk "ENGINE: following std script is copied: #{copy_log.join ' '}"
        end


        call_judge(problem_home,language,grading_dir,source_name)

        @reporter.report(submission,"#{grading_dir}/test-result")

        # unlock the directory
        dinit.teardown do
          copy_log = load_copy_log(problem_home)
          clear_copy_log(problem_home)
          clear_script(copy_log,problem_home)
        end

      rescue RuntimeError => msg
        @reporter.report_error(submission, msg)
        puts "ERROR: #{msg}"

      ensure
        @room_maker.clean_up(submission)
        Dir.chdir(current_dir)   # this is really important
      end
    end

    protected

    def talk(str)
      if @config.talkative
        puts str
      end
    end

    #change directory to problem_home
    #call the "judge" script
    def call_judge(problem_home,language,grading_dir,fname)
      ENV['PROBLEM_HOME'] = problem_home
      ENV['RUBYOPT'] = ''

      Dir.chdir grading_dir
      script_name = "#{problem_home}/script/judge"
      cmd = "#{script_name} #{language} #{fname}"
      talk "ENGINE: Calling Judge at #{cmd}"
      warn "ERROR: file does not exists #{script_name}" unless File.exists? script_name
      system(cmd)
    end

    def get_std_script_dir
      GRADER_ROOT + '/std-script'
    end

    #copy any script presented in std-script directory that is not in the problem_home
    #this allow a problem setter to provide their own version for each script
    #in case that they want to hack something
    def copy_script(problem_home)
      script_dir = "#{problem_home}/script"
      std_script_dir = get_std_script_dir

      raise "engine: std-script directory not found" if !FileTest.exist?(std_script_dir)

      scripts = Dir[std_script_dir + '/*']

      copied = []

      scripts.each do |s|
        fname = File.basename(s)
        next if FileTest.directory?(s)
        if !FileTest.exist?("#{script_dir}/#{fname}")
          copied << fname
          FileUtils.cp(s, "#{script_dir}", :preserve => true)
        end
      end

      return copied
    end

    def copy_log_filename(problem_home)
      return File.join(problem_home, '.scripts_copied')
    end

    def save_copy_log(problem_home, log)
      f = File.new(copy_log_filename(problem_home),"w")
      log.each do |fname|
        f.write("#{fname}\n")
      end
      f.close
    end

    def load_copy_log(problem_home)
      f = File.new(copy_log_filename(problem_home),"r")
      log = []
      f.readlines.each do |line|
        log << line.strip
      end
      f.close
      log
    end

    def clear_copy_log(problem_home)
      File.delete(copy_log_filename(problem_home))
    end

    def clear_script(log,problem_home)
      log.each do |s|
        FileUtils.rm("#{problem_home}/script/#{s}")
      end
    end

    def mkdir_if_does_not_exist(dirname)
      Dir.mkdir(dirname) if !FileTest.exist?(dirname)
    end
    
  end
  
end
