# Unit test for Gogrid gem
# Specify your gogrid account credentials as described in test_credentials.rb
# Will use the last ip returned by 'list_ips' to create test servers
require File.dirname(__FILE__) + '/../lib/right_gogrid'

class TestRightGogrid < Test::Unit::TestCase

  TEST_SERVER_NAME = "right_gogrid_awesome_test_server_1234567890"
  TEST_SERVER_IMAGE = "rhel51_64_php"
  TEST_SERVER_RAM = "512MB"
  TEST_SERVER_DESCRIPTION = "Test server"
  ADDED_TEST_SERVER_NAME = "right_gogrid_awesome_added_test_server"

  def setup
    TestCredentials.get_credentials
    @gogrid = Rightscale::Gogrid.new(TestCredentials.key, TestCredentials.secret)
  end

  # return a test IP from the list of IPs in the account
  # set default argument to free IP index
  def test_ip(index=258)
    ips = @gogrid.list_ips
    ips[index]["ip"]
    #puts ips.collect {|ip| ip["ip"] + ", " }
  end
 
  def add_test_server
    @gogrid.add_server(TEST_SERVER_NAME, TEST_SERVER_IMAGE, TEST_SERVER_RAM, test_ip, TEST_SERVER_DESCRIPTION)
  end

  def test_01_list_images
    result = @gogrid.list_images
    assert result.is_a?(Array)
  end
  
  def test_02_list_servers
    result = @gogrid.list_servers
    assert result.is_a?(Array)
  end
  
  def test_03_add_and_delete_server
    result = add_test_server
    assert result.is_a?(Array)
    result = @gogrid.gogrid_get_servers({:names=>[TEST_SERVER_NAME]})
    assert result.is_a?(Array)
    @gogrid.delete_server_by_name(TEST_SERVER_NAME)
    assert result.is_a?(Array)
  end
  
  def test_04_power_server
    add_test_server
    result = @gogrid.gogrid_power_server(:name=>TEST_SERVER_NAME,:power=>cycle)
    assert result.is_a?(Array)
    @gogrid.delete_server_by_name(TEST_SERVER_NAME)
  end
  
  def test_05_list_support_passwords
      result = @gogrid.list_support_passwords
      assert result.is_a?(Array)
  end

  def test_06_get_support_password
      passwords = @gogrid.list_support_passwords
      assert !passwords.empty?
      result = @gogrid.get_support_password(passwords[0]=>"id")
      assert result.is_a?(Array)
  end

  def test_07_list_common_lookup
    result = @gogrid.list_common_lookup
    assert result.is_a?(Array)
  end
  
  def test_08_list_loadbalancers
    result = @gogrid.list_loadbalancers
    assert result.is_a?(Array)
  end
  
  def test_09_add_and_delete_loadbalancer
    result = @gogrid.add_loadbalancer(
        "Test loadbalancer - delete", 
        test_ip(259),
        "80",
        [{:ip => test_ip, :port => "8080"}, {:ip => test_ip, :port => "443"}],
        "Test loadbalancer - delete",
        nil,
        "None")
    assert result.is_a?(Array)
    assert !result.empty?
    balancers = @gogrid.list_loadbalancers
    assert !balancers.empty?
    @gogrid.get_loadbalancer_by_id(balancers.first)
    assert result.is_a?(Array)
    result = @gogrid.delete_loadbalancer(result.first=>"id")
    assert result.is_a?(Array)
  end
  
  def test_10_get_myaccount_billing
    result = @gogrid.get_myaccount_billing
    assert result.is_a?(Array)
  end
end

