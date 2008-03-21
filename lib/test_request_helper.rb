#
# This part contains various test_request helpers for interfacing
# with Grader::Engine.  There are TestRequestRoomMaker and
# TestRequestReporter.

module Grader

  #
  # A TestRequestRoomMaker is a helper object for Engine
  # - finds grading room: in user_result_dir/(user)/test_request/ ...
  # - prepare problem configuration for grading --- basically it copy
  #   all config files, and copy user's input into the testcase
  #   directory.  First, it finds the template from problem template
  #   directory; if it can't find a template, it'll use the template
  #   from default template.
  class TestRequestRoomMaker
    def initialize
      @config = Grader::Configuration.get_instance
    end
    
    def produce_grading_room(test_request)
      grading_room = grading_room_dir(test_request)
      FileUtils.mkdir_p(grading_room)
      grading_room
    end
    
    def find_problem_home(test_request)
      problem_name = test_request.problem_name

      template_dir = "#{@config.test_request_problem_templates_dir}/" + problem_name

      raise "Test Request: error template not found" if !File.exists?(template_dir)
      
      problem_home = problem_home_dir(test_request)
      FileUtils.mkdir_p(problem_home)
      
      copy_problem_template(template_dir,problem_home)
      link_input_file(test_request,problem_home)

      problem_home
    end
    
    def save_source(test_request,source_name)
      dir = self.produce_grading_room(test_request)
      submission = test_request.submission
      f = File.open("#{dir}/#{source_name}","w")
      f.write(submission.source)
      f.close
    end
    
    def clean_up(test_request)
      problem_home = problem_home_dir(test_request)
      remove_data_files(problem_home)
    end
    
    protected
    def grading_room_dir(test_request)
      problem_name = test_request.problem_name
      user = test_request.user
      "#{@config.user_result_dir}" + 
        "/#{user.login}/test_request" +
        "/#{problem_name}/#{test_request.id}"
    end
    
    def problem_home_dir(test_request)
      problem_name = test_request.problem_name
      user = test_request.user
      "#{@config.user_result_dir}" + 
        "/#{user.login}/test_request/#{problem_name}"
    end
    
    def copy_problem_template(template_dir,problem_home)
      cmd = "cp -R #{template_dir}/* #{problem_home}"
      system_and_raise_when_fail(cmd,"Test Request: cannot copy problem template")
    end
    
    def link_input_file(test_request,problem_home)
      cmd = "ln -s #{test_request.input_file_name} #{problem_home}/test_cases/1/input-1.txt"
      system_and_raise_when_fail(cmd,"Test Request: cannot link input file")
    end
    
    def remove_data_files(problem_home)
      if File.exists?("#{problem_home}/test_cases/1/input-1.txt")
        cmd = "rm #{problem_home}/test_cases/1/*"
        system_and_raise_when_fail(cmd,"Test Request: cannot remove data files")
      end
    end
    
    def system_and_raise_when_fail(cmd,msg)
      if !system(cmd)
        raise msg
      end
    end
    
  end
  
  class TestRequestReporter
    def initialize
      @config = Grader::Configuration.get_instance
    end
    
    def report(test_request,test_result_dir)
      save_result(test_request,read_result(test_result_dir))
    end

    def report_error(test_request, msg)
      save_result(test_request, {:running_stat => "#{msg}"})
    end
    
    protected
    def read_result(test_result_dir)
      # TODO:
      cmp_msg_fname = "#{test_result_dir}/compiler_message"
      cmp_file = File.open(cmp_msg_fname)
      cmp_msg = cmp_file.read
      cmp_file.close
      
      result_file_name = "#{test_result_dir}/1/result"

      if File.exists?(result_file_name)
        output_file_name = "#{test_result_dir}/1/output.txt"
        results = File.open("#{test_result_dir}/1/result").readlines
        stat = format_running_stat(results)

        return {
          :output_file_name => output_file_name,
          :running_stat => stat,
          :comment => "", 
          :cmp_msg => cmp_msg}
      else
        return {
          :running_stat => "",
          :comment => "Compilation error", 
          :cmp_msg => cmp_msg}
      end
    end

    def format_running_stat(results)
      running_time_line = results[-1]

      run_stat = ""
      if !(/[Cc]orrect/.match(results[0]))
        run_stat = results[0].chomp
      end

      if res = /r(.*)u(.*)s/.match(running_time_line)
        seconds = (res[1].to_f + res[2].to_f)
        time_stat = "Time used: #{seconds} sec."
      else
        time_stat = "Time used: n/a sec."
      end
      return "#{run_stat}\n#{time_stat}"
    end
    
    def save_result(test_request,result)
      if result[:output_file_name]!=nil
        test_request.output_file_name = link_output_file(test_request,
                                                         result[:output_file_name])
      end
      test_request.graded_at = Time.now
      test_request.compiler_message = (result[:cmp_msg] or '')
      test_request.grader_comment = (result[:comment] or '')
      test_request.running_stat = (result[:running_stat] or '')
      test_request.save
    end
    
    protected
    def link_output_file(test_request, fname)
      target_file_name = random_output_file_name(test_request.user,
                                                 test_request.problem)
      FileUtils.mkdir_p(File.dirname(target_file_name))
      cmd = "ln -s #{fname} #{target_file_name}"
      if !system(cmd)
        raise "TestRequestReporter: cannot move output file"
      end
      return target_file_name
    end

    def random_output_file_name(user,problem)
      problem_name = TestRequest.name_of(problem)
      begin
        tmpname =  "#{@config.test_request_output_base_dir}" +
          "/#{user.login}/#{problem_name}/#{rand(10000)}"
      end while File.exists?(tmpname)
      tmpname
    end

  end
  
end
