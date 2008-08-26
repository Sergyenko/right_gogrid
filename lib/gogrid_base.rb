
module Rightscale

  class GogridBenchmarkingBlock #:nodoc:
    attr_accessor :parser, :service
    def initialize
      # Benchmark::Tms instance for service (Ec2, S3, or SQS) access benchmarking.
      @service = Benchmark::Tms.new()
      # Benchmark::Tms instance for parsing benchmarking.
      @parser = Benchmark::Tms.new()
    end
  end

  class GogridNoChange < RuntimeError
  end

  class GogridJsonParser
    def parse(response)
      json = JSON.load(response.body)
      raise GogridError.new("Unsuccessful JSON response: #{json.inspect}") unless json["status"] == "success"
      json['list']
    end
  end

  # Dummy parser - does nothing
  # Returns the original response back
  class GogridDummyParser  # :nodoc:
    def parse(response)
      response
    end
  end

  module RightGogridInterface
    DEFAULT_GOGRID_URL = 'http://api.gogrid.com/api'
    DEFAULT_VERSION    = '1.0'
    DEFAULT_FORMAT     = 'json'

    # Text, if found in an error message returned by Gogrid, indicates that this may be a transient
    # error. Transient errors are automatically retried with exponential back-off.
    # TODO: gather Gogrid errors here
    GOGRID_PROBLEMS = [ #'Forbidden',
                        'internal service error',
                        'is currently unavailable',
                        'no response from',
                        'Please try again',
                        'InternalError',
                        'ServiceUnavailable', #from SQS docs
                        'Unavailable',
                        'This application is not currently available',
                        'InsufficientInstanceCapacity'
                       ]
    @@gogrid_problems = GOGRID_PROBLEMS
      # Returns a list of Amazon service responses which are known to be transient problems.
      # We have to re-request if we get any of them, because the problem will probably disappear.
      # By default this method returns the same value as the AMAZON_PROBLEMS const.
    def self.gogrid_problems
      @@gogrid_problems
    end

    @@caching = false
    def self.caching
      @@caching
    end
    def self.caching=(caching)
      @@caching = caching
    end

    @@bench = GogridBenchmarkingBlock.new
    def self.bench_parser
      @@bench.parser
    end
    def self.bench_gogrid
      @@bench.service
    end

      # Current Gogrig API key
    attr_reader :gogrig_api_key
      # Current Gogrig secret key
    attr_reader :gogrig_secret
      # Last HTTP request object
    attr_reader :last_request
      # Last HTTP response object
    attr_reader :last_response
      # Last Gogrid errors list (used by GogridErrorHandler)
    attr_accessor :last_errors
      # Logger object
    attr_accessor :logger
      # Initial params hash
    attr_accessor :params
      # RightHttpConnection instance
    attr_reader :connection
      # Cache
    attr_reader :cache


    #
    # Params:
    #   :gogrid_url
    #   :logger
    #   :multi_thread
    #
    def init(gogrig_api_key, gogrig_secret, params={}) #:nodoc:
      @params = params
      @cache  = {}
      @error_handler = nil
      # deny working without credentials
      if gogrig_api_key.blank? || gogrig_secret.blank?
        raise GogridError.new("GoGrid api and secret keys are required to operate on GoGrid API service")
      end
      @gogrid_api_key = gogrig_api_key
      @gogrid_secret  = gogrig_secret
      # parse Gogrid URL
      @params[:gogrid_url] ||= ENV['GOGRID_URL'] || DEFAULT_GOGRID_URL
      @params[:server]       = URI.parse(@params[:gogrid_url]).host
      @params[:port]         = URI.parse(@params[:gogrid_url]).port
      @params[:service]      = URI.parse(@params[:gogrid_url]).path
      @params[:protocol]     = URI.parse(@params[:gogrid_url]).scheme
      # other params
      @params[:multi_thread] ||= defined?(GOGRID_DAEMON)
      @logger = @params[:logger] || (defined?(RAILS_DEFAULT_LOGGER) && RAILS_DEFAULT_LOGGER) || Logger.new(STDOUT)
      @logger.info "New #{self.class.name} using #{@params[:multi_thread] ? 'multi' : 'single'}-threaded mode"
    end

    def on_exception(options={:raise=>true, :log=>true}) # :nodoc:
      raise if $!.is_a?(GogridNoChange)
      GogridError::on_gogrid_exception(self, options)
    end

    # --------
    # Helpers
    # --------

      # Return +true+ if this instance works in multi_thread mode and +false+ otherwise.
    def multi_thread
      @params[:multi_thread]
    end

    def cgi_escape_params(params) # :nodoc:
      params.map {|k,v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}" }.join("&")
    end

    def signature # :nodoc:
      Digest::MD5.hexdigest("#{@gogrid_api_key}#{@gogrid_secret}#{'%.0f'%Time.new.to_f}")
    end

    # ----------------------------------
    # request generation and processing
    # ----------------------------------

    def do_request(path, params={}, non_unique_params={}) # :nodoc:
      request_hash = generate_request(path, params, non_unique_params)
      # create a dafault response parser
      case request_hash[:format]
      when 'json' then parser = GogridJsonParser.new
#      when 'xml'
#      when 'csv'
      else             raise "Unsupported request format: #{params['format']}"
      end
      # perform a request
      request_info(request_hash, parser)
    end

    # Generate a handy request hash.
    def generate_request(path, params={}, non_unique_params={}) # :nodoc:
      # default request params
      params = { 'format'  => DEFAULT_FORMAT,
                 'v'       => DEFAULT_VERSION,
                 'sig'     => signature,
                 'api_key' => @gogrid_api_key}.merge(params)
      # encode key/values
      normal_params = cgi_escape_params(params)
      # add the non_unique params at the end if we've received some
      other_params = non_unique_params.collect do |i|
        k = i.keys[0];
        v = i.values[0];
        "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}"
      end.join("&")
      other_params = "&#{other_params}" unless other_params.blank?
      # create url and request
      request_url = "#{@params[:service]}/#{path}?#{normal_params}#{other_params}"
      request     = Net::HTTP::Get.new(request_url)
      # prepare output hash
      { :request  => request,
        :server   => @params[:server],
        :port     => @params[:port],
        :protocol => @params[:protocol],
        :format   => params['format'] }
    end

    # Perform a request.
    # (4xx and 5xx error handling is being made through GogridErrorHandler)
    def request_info(request, parser)  #:nodoc:
      # check single/multi threading mode
      thread = @params[:multi_thread] ? Thread.current : Thread.main
      # create a connection if needed
      thread[:ec2_connection] ||= Rightscale::HttpConnection.new(:exception => GogridError, :logger => @logger)
      @connection    = thread[:ec2_connection]
      @last_request  = request[:request]
      @last_response = nil
      # perform a request
      @@bench.service.add!{ @last_response = @connection.request(request) }
      # check response for success...
      if @last_response.is_a?(Net::HTTPSuccess)
        @error_handler = nil
        result         = nil
        @@bench.parser.add! { result = parser.parse(@last_response) }
        return result
      else
        @error_handler ||= GogridErrorHandler.new(self, parser, :errors_list => @@gogrid_problems)
        check_result     = @error_handler.check(request)
        if check_result
          @error_handler = nil
          return check_result
        end
        raise GogridError.new(@last_errors, @last_response.code)
      end
    rescue
      @error_handler = nil
      raise
    end

    # --------
    # Caching
    # --------

    # Perform a request.
    # Skips a response parsing if caching is used.
    def request_cache_or_info(method, request_hash, parser_class, use_cache=true) #:nodoc:
      # We do not want to break the logic of parsing hence will use a dummy parser to process all the standart
      # steps (errors checking etc). The dummy parser does nothig - just returns back the params it received.
      # If the caching is enabled and hit then throw  GogridNoChange.
      # P.S. caching works for the whole images list only! (when the list param is blank)
      response = request_info(request_hash, GogridDummyParser.new)
      # check cache
      cache_hits?(method.to_sym, response.body) if use_cache
      result = nil
      @@bench.parser.add!{ result = parser_class.new.parse(response) }
      result = yield(result) if block_given?
      # update parsed data
      update_cache(method.to_sym, :parsed => result) if use_cache
      result
    end

    # Returns +true+ if the describe_xxx responses are being cached
    def caching?
      @params.key?(:cache) ? @params[:cache] : @@caching
    end

    # Check if the gogrid function response hits the cache or not.
    # If the cache hits:
    # - raises an +GogridNoChange+ exception if +do_raise+ == +:raise+.
    # - returnes parsed response from the cache if it exists or +true+ otherwise.
    # If the cache miss or the caching is off then returns +false+.
    def cache_hits?(function, response, do_raise=:raise) # :nodoc:
      result = false
      if caching?
        function     = function.to_sym
        response_md5 = MD5.md5(response).to_s
        # well, the response is new, reset cache data
        unless @cache[function] && @cache[function][:response_md5] == response_md5
          update_cache(function, {:response_md5 => response_md5,
                                  :timestamp    => Time.now,
                                  :hits         => 0,
                                  :parsed       => nil})
        else
          # aha, cache hits, update the data and throw an exception if needed
          @cache[function][:hits] += 1
          if do_raise == :raise
            raise(GogridNoChange, "Cache hit: #{function} response has not changed since "+
                                  "#{@cache[function][:timestamp].strftime('%Y-%m-%d %H:%M:%S')}, "+
                                  "hits: #{@cache[function][:hits]}.")
          else
            result = @cache[function][:parsed] || true
          end
        end
      end
      result
    end

    def update_cache(function, hash) # :nodoc:
      (@cache[function.to_sym] ||= {}).merge!(hash) if caching?
    end
  end
end



  # Exception class to signal any Amazon errors. All errors occuring during calls to Amazon's
  # web services raise this type of error.
  # Attribute inherited by RuntimeError:
  #  message    - the text of the error
  class GogridError < RuntimeError # :nodoc:

    # either an array of errors where each item is itself an array of [code, message]),
    # or an error string if the error was raised manually, as in <tt>GogridError.new('err_text')</tt>
    attr_reader :errors

    # Response HTTP error code
    attr_reader :http_code

    def initialize(errors=nil, http_code=nil)
      @errors      = errors
      @http_code   = http_code
      super(@errors.is_a?(Array) ? @errors.map{|code, msg| "#{code}: #{msg}"}.join("; ") : @errors.to_s)
    end

    # Does any of the error messages include the regexp +pattern+?
    # Used to determine whether to retry request.
    def include?(pattern)
      if @errors.is_a?(Array)
        @errors.each{ |code, msg| return true if code =~ pattern }
      else
        return true if @errors_str =~ pattern
      end
      false
    end

    # Generic handler for GogridErrors.
    # object that caused the exception (it must provide last_request and last_response). Supported
    # boolean options are:
    # * <tt>:log</tt> print a message into the log using gogrid.logger to access the Logger
    # * <tt>:puts</tt> do a "puts" of the error
    # * <tt>:raise</tt> re-raise the error after logging
    def self.on_gogrid_exception(gogrid, options={:raise=>true, :log=>true})
 	    # Only log & notify if not user error
      if !options[:raise] || system_error?($!)
        error_text = "#{$!.inspect}\n#{$@}.join('\n')}"
        puts error_text if options[:puts]
          # Log the error
        if options[:log]
          request  = gogrid.last_request  ? gogrid.last_request.path :  '-none-'
          response = gogrid.last_response ? "#{gogrid.last_response.code} -- #{gogrid.last_response.message} -- #{gogrid.last_response.body}" : '-none-'
          gogrid.logger.error error_text
          gogrid.logger.error "Request was:  #{request}"
          gogrid.logger.error "Response was: #{response}"
        end
      end
      raise if options[:raise]  # re-raise an exception
      return nil
    end

    # True if e is an AWS system error, i.e. something that is for sure not the caller's fault.
    # Used to force logging.
    # TODO: Place Gogrid Errors here
    def self.system_error?(e)
 	    !e.is_a?(self) || e.message =~ /InternalError|InsufficientInstanceCapacity|Unavailable/
    end

  end

  class GogridErrorHandler # :nodoc:
    # 0-100 (%)
    DEFAULT_CLOSE_ON_4XX_PROBABILITY = 10

    @@reiteration_start_delay = 0.2
    def self.reiteration_start_delay
      @@reiteration_start_delay
    end
    def self.reiteration_start_delay=(reiteration_start_delay)
      @@reiteration_start_delay = reiteration_start_delay
    end

    @@reiteration_time = 5
    def self.reiteration_time
      @@reiteration_time
    end
    def self.reiteration_time=(reiteration_time)
      @@reiteration_time = reiteration_time
    end

    @@close_on_error = true
    def self.close_on_error
      @@close_on_error
    end
    def self.close_on_error=(close_on_error)
      @@close_on_error = close_on_error
    end

    @@close_on_4xx_probability = DEFAULT_CLOSE_ON_4XX_PROBABILITY
    def self.close_on_4xx_probability
      @@close_on_4xx_probability
    end
    def self.close_on_4xx_probability=(close_on_4xx_probability)
      @@close_on_4xx_probability = close_on_4xx_probability
    end

    # params:
    #  :reiteration_time
    #  :errors_list
    #  :close_on_error           = true | false
    #  :close_on_4xx_probability = 1-100
    def initialize(gogrid, parser, params={}) #:nodoc:
      @gogrid        = gogrid           
      @parser        = parser           # parser to parse Amazon response
      @started_at    = Time.now
      @stop_at       = @started_at  + (params[:reiteration_time] || @@reiteration_time)
      @errors_list   = params[:errors_list] || []
      @reiteration_delay = @@reiteration_start_delay
      @retries       = 0
      # close current HTTP(S) connection on 5xx, errors from list and 4xx errors
      @close_on_error           = params[:close_on_error].nil? ? @@close_on_error : params[:close_on_error]
      @close_on_4xx_probability = params[:close_on_4xx_probability] || @@close_on_4xx_probability
    end

      # Returns false if
    def check(request)  #:nodoc:
      result           = false
      error_found      = false
      error_match      = nil
      last_errors_text = ''
      response         = @gogrid.last_response
      # log error
      request_text_data = "#{request[:server]}:#{request[:port]}#{request[:request].path}"
      @gogrid.logger.warn("##### #{@gogrid.class.name} returned an error: #{response.code} #{response.message}\n#{response.body} #####")
      @gogrid.logger.warn("##### #{@gogrid.class.name} request: #{request_text_data} ####")

      @gogrid.last_errors = [[response.code, "#{response.message} (#{request_text_data})"]]
      last_errors_text    = response.message
      # now - check the error
      @errors_list.each do |error_to_find|
        if last_errors_text[/#{error_to_find}/i]
          error_found = true
          error_match = error_to_find
          @gogrid.logger.warn("##### Retry is needed, error pattern match: #{error_to_find} #####")
          break
        end
      end
        # check the time has gone from the first error come
      if error_found
        # Close the connection to the server and recreate a new one.
        # It may have a chance that one server is a semi-down and reconnection
        # will help us to connect to the other server
        if @close_on_error
          @gogrid.connection.finish "#{self.class.name}: error match to pattern '#{error_match}'"
        end

        if (Time.now < @stop_at)
          @retries += 1

          @gogrid.logger.warn("##### Retry ##{@retries} is being performed. Sleeping for #{@reiteration_delay} sec. Whole time: #{Time.now-@started_at} sec ####")
          sleep @reiteration_delay
          @reiteration_delay *= 2

          # Always make sure that the fp is set to point to the beginning(?)
          # of the File/IO. TODO: it assumes that offset is 0, which is bad.
          if(request[:request].body_stream && request[:request].body_stream.respond_to?(:pos))
            begin
              request[:request].body_stream.pos = 0
            rescue Exception => e
              @logger.warn("Retry may fail due to unable to reset the file pointer" +
                           " -- #{self.class.name} : #{e.inspect}")
            end
          end
          result = @gogrid.request_info(request, @parser)
        else
          @gogrid.logger.warn("##### Ooops, time is over... ####")
        end
      # aha, this is unhandled error:
      elsif @close_on_error
        # Is this a 5xx error ?
        if @gogrid.last_response.code.to_s[/^5\d\d$/]
          @gogrid.connection.finish "#{self.class.name}: code: #{@gogrid.last_response.code}: '#{@gogrid.last_response.message}'"
        # Is this a 4xx error ?
        elsif @gogrid.last_response.code.to_s[/^4\d\d$/] && @close_on_4xx_probability > rand(100)
          @gogrid.connection.finish "#{self.class.name}: code: #{@gogrid.last_response.code}: '#{@gogrid.last_response.message}', " +
                                 "probability: #{@close_on_4xx_probability}%"
        end
      end
      result
    end

  end
