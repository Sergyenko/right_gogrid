class TestCredentials

  @@key = nil 
  @@secret = nil 

  def self.key
    @@key
  end
  def self.key=(newval)
    @@key = newval
  end
  def self.secret
    @@secret
  end
  def self.secret=(newval)
    @@secret = newval
  end

# Make sure you have environment vars set:
# 
# export GOGRID_KEY ='your_gogrid_key'
# export GOGRID_SECRET ='your_gogrid_secret'
#
# or you have a file: ~/.rightscale/test_gogrid_credentials.rb with text:
# 
#  TestCredentials.key = 'your_gogrid_key'
#  TestCredentials.secret = 'your_gogrid_secret'
#
  def self.get_credentials
    Dir.chdir do
      begin
        Dir.chdir('./.rightscale') do 
          require 'test_gogrid_credentials'
        end
      rescue Exception => e
        puts "Couldn't chdir to ~/.rightscale: #{e.message}"
      end
    end
  end

end
