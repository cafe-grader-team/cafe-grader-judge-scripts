
module Grader

  class Configuration

    private_class_method :new

    attr_accessor :problems_dir
    attr_accessor :user_result_dir
    attr_accessor :talkative
    attr_accessor :report_grader
    attr_accessor :grader_hostname    
    attr_accessor :report_comment
    attr_accessor :rails_env

    @@instance = nil

    def self.get_instance
      if @@instance==nil
        @@instance = new
      end
      @@instance
    end
    
    private
    def initialize
      @talkative = false
      @report_grader = false
      @grader_hostname = `hostname`.chomp

      @rails_env = 'development'
      
      @report_comment = lambda { |comment| comment }
    end

  end

end
