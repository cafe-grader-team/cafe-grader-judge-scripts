
module Grader

  class Engine

    def initialize(grader_process=nil)
      @config = Grader::Configuration.get_instance
      @grader_process = grader_process
    end

    def grade(sub)
      current_dir = `pwd`.chomp

      submission_id = sub.id
      user = sub.user
      problem = sub.problem

      # TODO: will have to create real exception for this
      raise "improper submission" if user==nil or problem==nil
      
      language = sub.language.name
      lang_ext = sub.language.ext
      # FIX THIS
      talk 'some hack on language'
      if language == 'cpp'
        language = 'c++'
      end

      user_dir = "#{@config.user_result_dir}/#{user.login}"
      problem_out_dir = "#{user_dir}/#{problem.name}"
      submission_out_dir = "#{user_dir}/#{problem.name}/#{submission_id}"

      mkdir_if_does_not_exist(user_dir)
      mkdir_if_does_not_exist(problem_out_dir)
      mkdir_if_does_not_exist(submission_out_dir)

      problem_home = "#{@config.problems_dir}/#{problem.name}"
      source_name = "#{problem.name}.#{lang_ext}"
      
      save_source(sub,submission_out_dir,source_name)
      
      copy_log = copy_script(problem_home)
      
      call_judge(problem_home,language,submission_out_dir,source_name)
      save_result(sub,read_result("#{submission_out_dir}/test-result"))
      
      clear_script(copy_log,problem_home)
      
      Dir.chdir(current_dir)
    end

    def grade_oldest_task
      task = Task.get_inqueue_and_change_status(Task::STATUS_GRADING)
      if task!=nil 
        @grader_process.report_active(task) if @grader_process!=nil
    
        submission = Submission.find(task.submission_id)
        grade(submission)
        task.status_complete!
      end
      return task
    end

    def grade_problem(problem)
      users = User.find(:all)
      users.each do |u|
        puts "user: #{u.login}"
        last_sub = Submission.find(:first,
                                   :conditions => "user_id = #{u.id} and " +
                                                  "problem_id = #{prob.id}",
                                   :order => 'submitted_at DESC')
        if last_sub!=nil
          grade(last_sub)
        end
      end
    end

    protected
    
    def talk(str)
      if @config.talkative
        puts str
      end
    end

    def save_source(submission,dir,fname)
      f = File.open("#{dir}/#{fname}","w")
      f.write(submission.source)
      f.close
    end

    def call_judge(problem_home,language,submission_out_dir,fname)
      ENV['PROBLEM_HOME'] = problem_home
      
      talk submission_out_dir
      Dir.chdir submission_out_dir
      cmd = "#{problem_home}/script/judge #{language} #{fname}"
      talk "CMD: #{cmd}"
      system(cmd)
    end

    def read_result(test_result_dir)
      cmp_msg_fname = "#{test_result_dir}/compiler_message"
      cmp_file = File.open(cmp_msg_fname)
      cmp_msg = cmp_file.read
      cmp_file.close
      
      result_fname = "#{test_result_dir}/result"
      comment_fname = "#{test_result_dir}/comment"  
      if FileTest.exist?(result_fname)
        result_file = File.open(result_fname)
        result = result_file.readline.to_i
        result_file.close
        
        comment_file = File.open(comment_fname)
        comment = comment_file.readline.chomp
        comment_file.close
        
        return {:points => result, 
          :comment => comment, 
          :cmp_msg => cmp_msg}
      else
        return {:points => 0,
          :comment => 'compile error',
          :cmp_msg => cmp_msg}
      end
    end
    
    def save_result(submission,result)
      problem = submission.problem
      submission.graded_at = Time.now
      points = result[:points]
      submission.points = points
      comment = @config.report_comment.call(result[:comment])
      if problem == nil
        submission.grader_comment = 'PASSED: ' + comment + '(problem is nil)'
      elsif points == problem.full_score
        submission.grader_comment = 'PASSED: ' + comment
      else
        submission.grader_comment = 'FAILED: ' + comment
      end
      submission.compiler_message = result[:cmp_msg]
      submission.save
    end
    
    def get_std_script_dir
      GRADER_ROOT + '/std-script'
    end

    def copy_script(problem_home)
      script_dir = "#{problem_home}/script"
      std_script_dir = get_std_script_dir

      raise "std-script directory not found" if !FileTest.exist?(std_script_dir)

      scripts = Dir[std_script_dir + '/*']
      
      copied = []

      scripts.each do |s|
        fname = File.basename(s)
        if !FileTest.exist?("#{script_dir}/#{fname}")
          copied << fname
          system("cp #{s} #{script_dir}")
        end
      end
      
      return copied
    end
    
    def clear_script(log,problem_home)
      log.each do |s|
        system("rm #{problem_home}/script/#{s}")
      end
    end

    def mkdir_if_does_not_exist(dirname)
      Dir.mkdir(dirname) if !FileTest.exist?(dirname)
    end
    
  end
  
end
