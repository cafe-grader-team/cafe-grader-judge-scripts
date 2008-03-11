#
# A runner drives the engine into various tasks.
# 

module Grader

  class Runner

    def initialize(engine, grader_process=nil)
      @engine = engine
      @grader_process = grader_process
    end

    def grade_oldest_task
      task = Task.get_inqueue_and_change_status(Task::STATUS_GRADING)
      if task!=nil 
        @grader_process.report_active(task) if @grader_process!=nil
        
        submission = Submission.find(task.submission_id)
        @engine.grade(submission)
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
          @engine.grade(last_sub)
        end
      end
    end

    def grade_oldest_test_request
      test_request = TestRequest.get_inqueue_and_change_status(Task::STATUS_GRADING)
      if test_request!=nil 
        @grader_process.report_active(test_request) if @grader_process!=nil
        
        @engine.grade(test_request)
        test_request.status_complete!
      end
      return test_request
    end

  end

end

