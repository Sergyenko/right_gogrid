#
# Copyright (c) 2007-2008 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'cgi'
#require 'net/http'
require 'benchmark'
require 'json'
require 'md5'

require 'rubygems'
require 'right_http_connection'

$:.unshift(File.dirname(__FILE__))
require 'benchmark_fix'
require 'support'
require 'gogrid_base'


module RightGogrid
  MAJOR = 0
  MINOR = 1
  TINY  = 0
  VERSION = [MAJOR, MINOR, TINY].join('.')
end


module Rightscale

  class Gogrid
    include RightGogridInterface

    def initialize(gogrig_api_key, gogrig_secret, params={})
      init gogrig_api_key, gogrig_secret, params
    end

    #--------------
    # Images
    #--------------
  
    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:grid.image.list
    #
    # Retrieve a list of existing images. Returns array of hashes describing the images or an exception:
    #
    # Required params:
    # (none)
    # Optional params:
    # (none)
    #
    # go = Rightscale::Gogrid.new(key, password)
    # go.grid_image_list #=> [
    #   {"name"=>"centos44_32_apache22php5",
    #     "friendlyName"=>"CentOS 4.4 (32-bit) w/ Apache 2.2 + PHP5",
    #     "id"=>1,
    #     "isActive"=>true,
    #     "description"=>"CentOS 4.4 (32-bit) w/ Apache 2.2 + PHP5",
    #     "isPublic"=>true,
    #     "object"=>"serverimage",
    #     "location"=>"centos44_32_apache22php5_"},
    #   {"name"=>"rhel4_32_apache22php5",
    #     "friendlyName"=>"RHEL 4 (32-bit) w/ Apache 2.2 + PHP5",
    #     "id"=>2,
    #     "isActive"=>true,
    #     "description"=>"RHEL 4 (32-bit) w/ Apache 2.2 + PHP5",
    #     "isPublic"=>true,
    #     "object"=>"serverimage",
    #     "location"=>"rhel4_32_apache22php5_"},
    #    ...
    #    {"name"=>"centos51_64_postgresql",
    #     "friendlyName"=>"CentOS 5.1 (64-bit) w/ PostgreSQL 8.1",
    #     "id"=>28,
    #     "isActive"=>true,
    #     "description"=>"CentOS 5.1 (64-bit) w/ PostgreSQL 8.1",
    #     "isPublic"=>true,
    #     "object"=>"serverimage",
    #     "location"=>"centos51_64_postgresql_"}
    #     ]
    #
    #  This method is cached.
    #
    def grid_image_list
      request_hash = generate_request("grid/image/list")
      request_cache_or_info(:grid_image_list, request_hash, GogridJsonParser)
    rescue
      on_exception
    end

    #--------------
    # Servers
    #--------------

    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:grid.server.list
    #
    # Retrieve a list of existing servers. Returns array of hashes describing the servers or an exception:
    #
    # Required params:
    # (none)
    # Optional params:
    # +server_type+ = (string) name or id of the type of servers to list. With server_type one
    #                 can filter the results of the list to display just web/app servers or just database servers. (e.g., 1234 or "Web Server")
    #                 To list possible server.type values, call  common.lookup.list  with lookup set to 'server.type'
    #
    #  go.grid_server_list #=> [
    #    { "name"=>"Example Web Server",
    #      "os"=> {...},
    #      "type"=> {"name"=>"Web Server", ...},
    #      "id"=>5075,
    #      "description"=>"Some more info here",
    #      "ip"=> {...},
    #      "ram"=> {...},
    #      "image"=> {...},
    #      "object"=>"server",
    #      "state"=> {...}
    #     }]
    #
    #  This method is cached (unless server_type defined).
    #
    def grid_server_list(server_type=nil)
      opts = {}
      opts["server.type"] = server_type if server_type
      request_hash = generate_request("grid/server/list", opts)
      request_cache_or_info(:grid_server_list, request_hash, GogridJsonParser, !server_type)
    rescue
      on_exception
    end

    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:grid.server.get
    #
    # Retrieves one or many server objects from your list of servers. Returns array of hashes describing the servers or an exception:
    #
    # Required params:
    #  (none required...except that at least 1 of the optional ones should be set)
    # Optional params:
    #   +:ids+     = (array of strings|int) The id(s) of the  server(s) to retrieve. If multiple input id parameters are specified, the API will retrieve the set of servers whose ids match the input parameter values.
    #   +:names+   = (array of strings) The name(s) of the server(s) to retrieve. If multiple input name parameters are specified, the API will retrieve the set of servers whose names match the input parameter values.
    #   +:servers+ = (array of strings|int) The id(s) or name(s) of the server(s) to retrieve. If multiple input server parameters are specified, the API will retrieve the set of servers whose ids or names match the input parameter values.
    #
    # go.grid_server_get(:names => ["Example Web Server"]) #=> [
    #    {"name"=>"Example Web Server",
    #     "os"=> {...},
    #     "type"=> {"name"=>"Web Server", ...},
    #     "id"=>5075,
    #     "description"=>"Some more info here",
    #     "ip"=> {...},
    #     "ram"=> {...},
    #     "image"=> {...},
    #     "object"=>"server",
    #     "state"=> {...}
    #     }]
    def grid_server_get(params={})
      param_list = [] # An array with single-key hash entries...
      [:ids, :names, :servers].each do |ptype|
        items     = params[ptype].to_a.flatten
        item_name = ptype.to_s.chop.to_sym
        param_list += items.map { |item| { item_name => item} }
      end
      do_request("grid/server/get", {}, param_list)
    rescue
      on_exception
    end

    def grid_server_get_by_id(*ids)
      grid_server_get(:ids => ids)
    end
    def grid_server_get_by_name(*names)
      grid_server_get(:names => names)
    end
    def grid_server_get_by_id_or_name(*servers)
      grid_server_get(:servers => servers)
    end


    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:grid.server.add
    #
    # Adds a single server to your grid. Returns array with one hash describing the new server or an exception:
    #
    # Required params:
    #   +name+  = (string) The friendly name of this  server.
    #   +image+ = (string) The desired server image's id or name.
    #             To list available server images, use grid_image_list.
    #   +ram+   = (string) The id or name of the desired ram option for this server.
    #             To list ram values, call common.lookup.list with lookup set to server.ram
    #   +ip+    = (strings) The initial public ip for this server.
    #
    # Optional params:
    #   +description+ = (string) Descriptive text to describe this  server.
    #
    # go.grid_server_add(:name => "From API",
    #                    :image => "rhel51_64_php",
    #                    :ram => "512MB",
    #                    :ip => "216.121.60.21",
    #                    :description => "My first API server" )  #=> [
    #    {"name"=>"From API",
    #     "os"=> {"name"=>"RHEL 5.1 (64-bit)",
    #             "id"=>9,
    #             "description"=>"RHEL Linux 5.1 (64-bit)",
    #             "object"=>"option"},
    #     "type"=> {"name"=>"Web Server", ...},
    #     "id"=>5075,
    #     "description"=>"My first API server",
    #     "ip"=> {...},
    #     "ram"=> {...},
    #     "image"=> {"name"=>"rhel51_64_php",
    #                 "id"=>20,
    #                 "description"=>"RHEL 5.1 (64-bit) w/ Apache 2.2 + PHP 5.1",
    #                 "object"=>"option"},
    #     "object"=>"server",
    #     "state"=> {...}
    #     }]
    #
    def grid_server_add(name, image, ram, ip, description='' )
      do_request("grid/server/add", { :name  => name,
                                      :image => image,
                                      :ram   => ram,
                                      :ip    => ip,
                                      :description => description } )
    rescue
      on_exception
    end


    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:grid.server.delete
    #
    # Deletes a single server from your grid. Returns array with one hash describing the deleted server or an exception:
    #
    # Required params:
    #  (none required...except that at least 1 of the optional ones should be set)
    # Optional params:
    #   +:id+ = (string|int) The id of the  server to delete.
    #   +:name+ = (string) The name of the server to delete.
    #   +:server+ (string|int) The id or name of the server to delete.
    #
    # go.grid_server_delete(:name => ["From API"]) #=> [
    #    {"name"=>"From API",
    #     "os"=> {...},
    #     "type"=> {"name"=>"Web Server", ...},
    #     "id"=>5075,
    #     "description"=>"My first API server",
    #     "ip"=> {...},
    #     "ram"=> {...},
    #     "image"=> {},
    #     "object"=>"server",
    #     "state"=> {...}
    #     }]
    def grid_server_delete(params)
      #TODO: ensure at least 1 arg is set? (or handle the response appropriately)
      do_request("grid/server/delete", params)
    rescue
      on_exception
    end

    def grid_server_delete_by_id(id)
      grid_server_delete(:id => id)
    end
    def grid_server_delete_by_name(name)
      grid_server_delete(:name => name)
    end
    def grid_server_delete_by_id_or_name(id_or_name)
      grid_server_delete(:server => id_or_name)
    end

    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:grid.server.power
    #
    # Issues a power command to a single server in your grid or returns an exception:
    #
    # Required params:
    #   +:power+ = (string|symbol) Type of power operation to invoke. Supported types:
    #               :on | :start - To start a server
    #               :off| :stop  - To stop (shutdown) a server
    #               :cycle | :restart - To restart a server
    #
    # Optional params: NOTE that while they're "optional" there needs to be at least 1 set
    #   +:id+ = (string|int) The id of the server to which the power opperation will be performed.
    #   +:name+ = (string) The name of the server to which the power opperation will be performed.
    #   +:server+ (string|int) The id or name of the server to which the power opperation will be performed.
    #
    # go.grid_server_power(:power => "start", :name => ["From API"]) #=> [
    #    {"name"=>"From API",
    #     "os"=> {...},
    #     "type"=> {"name"=>"Web Server", ...},
    #     "id"=>5075,
    #     "description"=>"My first API server",
    #     "ip"=> {...},
    #     "ram"=> {...},
    #     "image"=> {},
    #     "object"=>"server",
    #     "state"=> {...}
    #     }]
    def grid_server_power(params)
      do_request("grid/server/power",params)
    rescue
      on_exception
    end

    def grid_server_power_by_id(id, power=:on)
      grid_server_power(:id => id, :power => power)
    end
    def grid_server_power_by_name(name, power=:on)
      grid_server_power(:name => name, :power => power)
    end
    def grid_server_power_by_id_or_name(id_or_name, power=:on)
      grid_server_power(:server => id_or_name, :power => power)
    end

    #--------------
    # IPs
    #--------------

    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:grid.ip.list
    #
    # Returns a (possibly filtered) list of available IPs in your grid or an exception.
    #
    # Required params:
    # (none)
    # Optional params:
    #   +:state+ = (string) Filtering parameter to limit the returned ips based on state
    #                 e.g., "Assigned", "Unassigned"
    #                 To list ip state values, call common.lookup.list with lookup set to ip.state
    #   +:type+  = (string) Filtering parameter to limit the returned ips based on type
    #                 e.g., "Public","Private"
    #                 To list ip type values, call common.lookup.list with lookup set to ip.type
    #
    #
    #  go.grid_ip_list(:type => "Public", :state => "Assigned") #=>
    #        [{"public"=>true,
    #          "id"=>138273,
    #          "ip"=>"216.121.60.16",
    #          "subnet"=>"216.121.60.16/255.255.255.240",
    #          "object"=>"ip"},
    #         ...
    #         {"public"=>true,
    #          "id"=>138288,
    #          "ip"=>"216.121.60.31",
    #          "subnet"=>"216.121.60.16/255.255.255.240",
    #          "object"=>"ip"
    #          }]
    #
    #  This method is cached (unless state and type defined).
    #
    def grid_ip_list(state=nil, type=nil)
      #In this one we'll convert keys to string since they require a "." in it (not supported by symbols)
      opts = {}
      opts["ip.state"] = state if state
      opts["ip.type"]  = type  if type
      request_hash = generate_request("grid/ip/list", opts)
      request_cache_or_info(:grid_ip_list, request_hash, GogridJsonParser, !(state || type))
    rescue
      on_exception
    end

    #--------------
    # Misc
    #--------------

    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:support.password.list
    #
    # Returns the list all the  passwords registered in the system or an exception
    #
    # Required params:
    # (none)
    # Optional params:
    # (none)
    #
    # go.support_password_list #=>
    #      [{"username"=>"root",
    #        "id"=>5415,
    #        "server"=>
    #         {"name"=>"From API",
    #          ...
    #          },
    #        "object"=>"password",
    #        "password"=>"abcdefghi",
    #        "applicationtype"=>"os"},
    #       {"username"=>"root",
    #        "id"=>5252,
    #        "server"=>
    #         {"name"=>"Example Server",
    #          ...
    #          },
    #        "object"=>"password",
    #        "password"=>"abcdefghi",
    #        "applicationtype"=>"os"}]
    #
    def support_password_list
      request_hash = generate_request("support/password/list")
      request_cache_or_info(:support_password_list, request_hash, GogridJsonParser)
    rescue
      on_exception
    end

    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:support.password.get
    #
    # Returns a single password registered in the system or an exception
    #
    # Required params:
    #  +id+ = (string) The id of the password to retrieve
    #
    # go.support_password_get (:id => 5415) #=>
    #      [{"username"=>"root",
    #        "id"=>5415,
    #        "server"=>
    #         {"name"=>"From API",
    #          ...
    #          },
    #        "object"=>"password",
    #        "password"=>"abcdefghi",
    #        "applicationtype"=>"os"}]
    #
    def support_password_get(id)
      do_request("support/password/get", :id => id)
    rescue
      on_exception
    end

    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:common.lookup.list
    #
    # Returns the list of options for a given lookup or an exception.
    # To list all the available lookups, set the parameter lookup to lookups.
    #
    # Required params:
    #   +lookup+ = (string) the type of lookup
    #              If set to "lookups" the call returns all the available lookups
    # Optional params:
    #   +sort+ = (string|symbol) the sort field [:id | :name | :description]
    #   +asc+  = (bool) if ordering in ascending mode [ :true | :false ]
    #
    #  go.common_lookup_list(:lookup => 'server.type', :sort => :name) #=>
    #    [{"name"=>"Database Server",
    #      "id"=>2,
    #      "description"=>
    #       "This server does not have a public connection to the Internet.",
    #      "object"=>"option"},
    #     {"name"=>"Web Server",
    #      "id"=>1,
    #      "description"=>"This server has a public connection to the Internet.",
    #      "object"=>"option"}]
    #
    #  This method is cached (unless lookup, sort and asc defined).
    #
    def common_lookup_list(lookup='lookups', sort=nil, asc=nil)
      opts = { :lookup => lookup }
      opts[:sort] = sort if sort
      opts[:asc]  = asc  if asc
      request_hash = generate_request("common/lookup/list", opts)
      request_cache_or_info(:common_lookup_list, request_hash, GogridJsonParser, lookup=='lookups' && !(sort || asc))
    rescue
      on_exception
    end

    #--------------
    # Balancers
    #--------------

    #
    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:grid.loadbalancer.list
    #
    # Returns the list of all loadbalancers in the system or an exception
    #
    # Required params:
    # (none)
    # Optional params:
    # (none)
    #
    #  go.grid_loadbalancer_list #=>
    #    [{"name"=>"API LB",
    #      "realiplist"=> [{"port"=>443,"ip"=> {...},
    #                      {"port"=>8080,"ip"=> {...}],
    #      "os"=> {"name"=>"F5", ...},
    #      "type"=> {"name"=>"Round Robin", ...},
    #      "virtualip"=> {"port"=>80,"ip"=> {...}},
    #      "persistence"=> {"name"=>"None", ...},
    #      "object"=>"loadbalancer",
    #      "state"=> {"name"=>"On", ...}
    #     }]
    #
    #  This method is cached.
    #
    def grid_loadbalancer_list
      request_hash = generate_request("grid/loadbalancer/list")
      request_cache_or_info(:grid_loadbalancer_list, request_hash, GogridJsonParser)
    rescue
      on_exception
    end


    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:grid.loadbalancer.get
    #
    # Retrieves one or many of your loadbalancers. Returns array of hashes describing the loadbalancers or an exception:
    #
    # Required params:
    #  (none required...except that at least 1 of the optional ones should be set)
    # Optional params:
    #   +:ids+ = (array of strings|int) The id(s) of the  loadbalancer(s) to retrieve. If multiple input id parameters are specified, the API will retrieve the set of loadbalancers whose ids match the input parameter values.
    #   +:names+ = (array of strings) The name(s) of the loadbalancer(s) to retrieve. If multiple input name parameters are specified, the API will retrieve the set of loadbalancers whose names match the input parameter values.
    #   +:loadbalancers+ = (array of strings|int) The id(s) or name(s) of the loadbalancer(s) to retrieve. If multiple input loadbalancer parameters are specified, the API will retrieve the set of loadbalancers whose ids or names match the input parameter values.
    #
    # go.grid_loadbalancer_get(:names => ["API LB"]) #=> [
    #    [{"name"=>"API LB",
    #      "realiplist"=> [{"port"=>443,"ip"=> {...},
    #                      {"port"=>8080,"ip"=> {...}],
    #      "os"=> {"name"=>"F5", ...},
    #      "type"=> {"name"=>"Round Robin", ...},
    #      "virtualip"=> {"port"=>80,"ip"=> {...}},
    #      "persistence"=> {"name"=>"None", ...},
    #      "object"=>"loadbalancer",
    #      "state"=> {"name"=>"On", ...}
    #     }]
    #
    def grid_loadbalancer_get(params={})
      param_list = [] # An array with single-key hash entries...
      [:ids, :names, :loadbalancers].each do |ptype|
        items     = params[ptype].to_a.flatten
        item_name = ptype.to_s.chop.to_sym
        param_list += items.map { |item| { item_name => item} }
      end
      do_request("grid/loadbalancer/get", {}, param_list)
    rescue
      on_exception
    end

    def grid_loadbalancer_get_by_id(*ids)
      grid_loadbalancer_get(:ids => ids)
    end
    def grid_loadbalancer_get_by_name(*names)
      grid_loadbalancer_get(:names => names)
    end
    def grid_loadbalancer_get_by_id_or_name(*ids_or_names)
      grid_loadbalancer_get(:loadbalancers => ids_or_names)
    end


    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:grid.loadbalancer.add
    #
    # Adds a single load balancer to your grid and returns its configuration or an exception.
    #
    # # Required params:
    #   +:name+ = (string) The name of this  load balancer.
    #   +:virtual_ip+ = (hash) The IPv4 and port of the virtual IP for this load balancer. This must be a publicly available IP.
    #                   :ip => ipv4 (string)
    #                   :port => port (string|integer)
    #                  e.g., {:ip => "200.100.50.1", :port => "80}
    #   +:real_ips+ (array)	The list of IP/port tuples in the real IP list for this load balancer.
    #                       Each tuple in the array will follow the same structure if the virtual_ip parameter:
    #                       :ip => ipv4 (string)
    #                       :port => port (string|integer)
    #                       e.g., [{:ip => "200.100.50.1", :port => "80} , {:ip => "1.2.3.4", :port => "8080}]
    # Optional params:
    #   +:description+ = (string) 	Descriptive text to describe this load balancer.
    #   +:type+ = (string) 	The load balancer type. This can be an int or string representing the load balancer option's id or name respectively.
    #             * Default is none
    #   +:persistence+ = (string) The persistence type to use. This can be an int or string representing the load balancer persistence types option's id or name respectively.
    #                    * Default is round robin.
    #                    * To list persistence values, call common.lookup.list with lookup set to loadbalancer.persistence
    #
    #  go.grod_loadbalancer_add(:name => "API LB",
    #                           :virtual_ip => {:ip => "216.121.60.25", :port => "80"},
    #                           :real_ips =>  [{:ip => "216.121.60.18", :port => "8080"},
    #                                           {:ip => "216.121.60.19", :port => "443"}],
    #                           :persistence => "None") !=>
    #    [{"name"=>"API LB",
    #      "realiplist"=> [{"port"=>443,"ip"=> {...},
    #                      {"port"=>8080,"ip"=> {...}],
    #      "os"=> {"name"=>"F5", ...},
    #      "type"=> {"name"=>"Round Robin", ...},
    #      "virtualip"=> {"port"=>80,"ip"=> {...}},
    #      "persistence"=> {"name"=>"None", ...},
    #      "object"=>"loadbalancer",
    #      "state"=> {"name"=>"On", ...}
    #     }]
    #
    def grid_loadbalancer_add(name, virtual_ip, virtual_port, real_ips, description=nil, type=nil, persistence=nil )
      # mandatory
      opts = { :name            => name,
               "virtualip.ip"   => virtual_ip,
               "virtualip.port" => virtual_port}
      # optional
      opts[:description] = description if description
      opts[:type]        = type        if type
      opts[:persistence] = persistence if persistence

      real_ip_tuples = real_ips # It's an array of 2 item hashes [{:ip=>"216.121.60.18",:port=>"8080"},{:ip=>"200.100.50.1",:port=>"80"} ]
      extra_opts = []
      if real_ip_tuples && real_ip_tuples.length > 0
        index=-1
        real_ip_tuples.each do |tuple|
          extra_opts << {"realiplist.#{index += 1}.ip" => tuple[:ip]}
          extra_opts << {"realiplist.#{index}.port"    => tuple[:port]}
        end
      end
      do_request("grid/loadbalancer/add", opts, extra_opts)
    rescue
      on_exception
    end

    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:grid.loadbalancer.delete
    #
    # Deletes a single loadbalancer from your grid. Returns array with one hash describing the deleted loadbalancer or an exception:
    #
    # Required params:
    #  (none required...except that at least 1 of the optional ones should be set)
    # Optional params:
    #   +:id+ = (string|int) The id of the loadbalancer to delete.
    #   +:name+ = (string) The name of the loadbalancer to delete.
    #   +:loadbalancer+ (string|int) The id or name of the loadbalancer to delete.
    #
    # go.grid_loadbalancer_delete(:name => ["From API"]) #=> [
    #    [{"name"=>"API LB",
    #      "realiplist"=> [{"port"=>443,"ip"=> {...},
    #                      {"port"=>8080,"ip"=> {...}],
    #      "os"=> {"name"=>"F5", ...},
    #      "type"=> {"name"=>"Round Robin", ...},
    #      "virtualip"=> {"port"=>80,"ip"=> {...}},
    #      "persistence"=> {"name"=>"None", ...},
    #      "object"=>"loadbalancer",
    #      "state"=> {"name"=>"On", ...}
    #     }]
    #
    def grid_loadbalancer_delete(params)
      do_request("grid/loadbalancer/delete",params)
    rescue
      on_exception
    end

    def grid_loadbalancer_delete_by_id(id)
      grid_loadbalancer_delete(:id => id)
    end
    def grid_loadbalancer_delete_by_name(name)
      grid_loadbalancer_delete(:name => name)
    end
    def grid_loadbalancer_delete_by_id_or_name(id_or_name)
      grid_loadbalancer_delete(:loadbalancer => id_or_name)
    end

    #--------------
    # Billing
    #--------------

    #
    # GoGrid API: http://wiki.gogrid.com/wiki/index.php/API:myaccount.billing.get
    #
    # Returns single billing summary or an exception
    #
    # Required params:
    # (none)
    # Optional params:
    # (none)
    #
    #  go.myaccount_billing_get #=>
    #     [{"transferOverage"=>0,
    #     "transferOverageCharge"=>0,
    #     "memoryAccrued"=>504,
    #     "memoryOverage"=>11,
    #     "transferAllotment"=>0,
    #     "memoryInUse"=>0.5,
    #     "startDate"=>nil,
    #     "memoryAllotment"=>0,
    #     "memoryOverageCharge"=>2.08999997377396,
    #     "endDate"=>nil,
    #     "object"=>"billingsummary"}]
    #
    def myaccount_billing_get
      do_request("myaccount/billing/get",{})
    rescue
      on_exception
    end

  end
end