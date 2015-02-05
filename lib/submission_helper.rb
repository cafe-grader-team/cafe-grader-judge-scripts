module Grader

  class SubmissionRoomMaker
    def initialize
      @config = Grader::Configuration.get_instance
    end
    
    def produce_grading_room(submission)
      user = submission.user
      problem = submission.problem
      grading_room = "#{@config.user_result_dir}/" + 
        "#{user.login}/#{problem.name}/#{submission.id}"
      
      FileUtils.mkdir_p(grading_room)
      grading_room
    end
    
    def find_problem_home(submission)
      problem = submission.problem
      "#{@config.problems_dir}/#{problem.name}"
    end

    def save_source(submission,source_name)
      dir = self.produce_grading_room(submission)
      f = File.open("#{dir}/#{source_name}","w")
      f.write(submission.source)
      f.close
    end

    def clean_up(submission)
    end
  end
  
  class SubmissionReporter
    def initialize(options={})
      options = {:dry_run => false, :result_collector => nil}.merge(options)
      @config = Grader::Configuration.get_instance
      @dry_run = options[:dry_run]
      @result_collector = options[:result_collector]
    end
    
    def report(sub,test_result_dir)
      result = read_result(test_result_dir)
      if @result_collector
        @result_collector.save(sub,                               
                               result)
      end
      save_result(sub,result)
    end
    
    def report_error(sub,msg)
      save_result(sub,{:points => 0,
                    :comment => "Grading error: #{msg}" })
    end

    protected
    def read_result(test_result_dir)
      cmp_msg_fname = "#{test_result_dir}/compiler_message"
      if FileTest.exist?(cmp_msg_fname)
        cmp_file = File.open(cmp_msg_fname)
        cmp_msg = cmp_file.read
        cmp_file.close
      else
        cmp_msg = ""
      end
      
      result_fname = "#{test_result_dir}/result"
      comment_fname = "#{test_result_dir}/comment"
      runstat_fname = "#{test_result_dir}/run_stat"
      if FileTest.exist?(result_fname)
        comment = ""
        begin
          result_file = File.open(result_fname)
          result = result_file.readline.to_i
          result_file.close
        rescue
          result = 0
          comment = "error reading result file."
        end
          
        begin
          comment_file = File.open(comment_fname)
          comment += comment_file.readline.chomp
          comment_file.close
        rescue
          comment += ""
        end

        begin
          runstat_file = File.open(runstat_fname)
          max_runtime = runstat_file.readline.to_f
          peak_memory = runstat_file.readline.to_i
        rescue
          max_runtime = -1
          peak_memory = -1
        end


        return {points: result,
          comment: comment,
          cmp_msg: cmp_msg,
          max_runtime: max_runtime,
          peak_memory: peak_memory
        }
      else
        if FileTest.exist?("#{test_result_dir}/a.out")
          return {:points => 0,
            :comment => 'error during grading',
            :cmp_msg => cmp_msg}
        else
          return {:points => 0,
            :comment => 'compilation error',
            :cmp_msg => cmp_msg}
        end
      end
    end
    
    def save_result(submission,result)
      problem = submission.problem
      submission.graded_at = Time.now.gmtime
      points = result[:points]
      submission.points = points
      comment = @config.report_comment(result[:comment])

      submission.peak_memory = result[:peak_memory]
      submission.max_runtime =  result[:max_runtime]
      submission.effective_code_length =submission.source.length

      #
      # TODO: FIX THIS MESSAGE
      #
      if problem == nil
        submission.grader_comment = 'PASSED: ' + comment + '(problem is nil)'
      elsif points == problem.full_score
        #submission.grader_comment = 'PASSED: ' + comment
        submission.grader_comment = comment
      elsif result[:comment].chomp =~ /^[\[\]P]+$/
        submission.grader_comment = 'PASSED: ' + comment + '(inconsistent score)'
      else
        #submission.grader_comment = 'FAILED: ' + comment
        submission.grader_comment = comment
      end
      submission.compiler_message = result[:cmp_msg] or ''

      if not @dry_run
        submission.save
      end
    end
    
  end
  
end
