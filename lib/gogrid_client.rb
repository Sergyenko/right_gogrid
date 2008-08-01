require 'digest/md5'
require 'cgi'
require 'net/http'

class GogridClient

  def initialize(base_uri,
                 apikey,
                 secret, 
                 format='json',
                 version='1.0')
    uri = URI.parse(base_uri || 'http://api.gogrid.com/api')
    @server = uri.host
    @port = uri.port
    @proto = uri.scheme
    @uri_prefix = uri.path
    @secret = secret
    @default_params = {'format'=>format, 'v'=>version,'api_key' => apikey}
  end    
  
  def getRequestPath(method,params,non_unique_params)
    requestURL = @uri_prefix+'/'+method+'?'
    call_params = @default_params.merge(params)
    call_params['sig']=getSignature(@default_params['api_key'],@secret)
    normal_params = encode_params(call_params)
    requestURL = requestURL+normal_params
    #add the non_unique params at the end if we've received some
    other_params = non_unique_params.collect{|i| k = i.keys[0]; v = i.values[0]; "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}" }.join("&") 
    requestURL = requestURL + (normal_params ? "&":"") + other_params if other_params
    requestURL
  end
  
  def getSignature(key,secret)
    Digest::MD5.hexdigest(key+secret+"%.0f"%Time.new.to_f)
  end
  
  def sendAPIRequest(method,params={},formatted_params = "")
    req_uri=getRequestPath(method,params,formatted_params)
    puts "REQ URL: #{req_uri}" 
    
    begin
       
      res = Net::HTTP.start(@server, @port) do |http|
        http.get(req_uri)
      end
    rescue Exception => e
      puts "EXCEPTION: #{e.inspect}"
      raise e
    end
    res
  end
  
  def encode_params(params)
    params.map {|k,v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}" }.join("&")
  end
    
end
