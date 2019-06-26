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
        @grader_process.report_inactive(task) if @grader_process!=nil
      end
      return task
    end

    # grade a specified problem for the latest submission of each user
    # optionally, on all submission when options[:all_sub] is set
    # optionally, only submission that has error (use when the problem itself has some problem)
    def grade_problem(problem, options={})
      user_index = 0
      user_count = User.count
      User.find_each do |u|
        puts "user: #{u.login} (#{user_index}/#{user_count})"
        user_index += 1
        if options[:user_conditions]!=nil
          con_proc = options[:user_conditions]
          next if not con_proc.call(u)
        end
        if options[:all_sub]
          Submission.where(user_id: u.id,problem_id: problem.id).find_each do |sub|
            next if options[:only_err] and sub.grader_comment != 'error during grading'
            @engine.grade(sub)
          end
        else
          last_sub = Submission.find_last_by_user_and_problem(u.id,problem.id)
          if last_sub!=nil
            @engine.grade(last_sub) unless options[:only_err] and last_sub.grader_comment != 'error during grading'
          end
        end
      end
    end

    def grade_submission(submission)
      puts "RUNNER: grade submission: #{submission.id} by #{submission.try(:user).try(:full_name)}"
      @engine.grade(submission)
    end

    def grade_oldest_test_request
      test_request = TestRequest.get_inqueue_and_change_status(Task::STATUS_GRADING)
      if test_request!=nil 
        @grader_process.report_active(test_request) if @grader_process!=nil

        @engine.grade(test_request)
        test_request.status_complete!
        @grader_process.report_inactive(test_request) if @grader_process!=nil
      end
      return test_request
    end

  end

end

