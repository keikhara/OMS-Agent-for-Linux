require 'fluent/test'
require_relative ENV['BASE_DIR'] + '/source/ext/fluentd/test/helper'
require_relative ENV['BASE_DIR'] + '/source/code/plugins/oms_configuration'
require_relative ENV['BASE_DIR'] + '/source/code/plugins/out_oms_api'
require_relative 'omstestlib'

class OutOMSApiTest < Test::Unit::TestCase

  # These keys should be loaded in environment variables
  TEST_WORKSPACE_ID=ENV['TEST_WORKSPACE_ID']
  TEST_SHARED_KEY=ENV['TEST_SHARED_KEY']

  def setup
    Fluent::Test.setup
    
    @base_dir = ENV['BASE_DIR']
    @ruby_test_dir = ENV['RUBY_TESTING_DIR']
    @prep_omsadmin = "#{ENV['BASE_DIR']}/test/installer/scripts/prep_omsadmin.sh"

    $log = OMS::MockLog.new
  end

  def teardown
    if @omsadmin_test_dir and File.directory? @omsadmin_test_dir
      FileUtils.rm_r @omsadmin_test_dir
      assert_equal(false, File.directory?(@omsadmin_test_dir))
    end
  end

  def prep_onboard
    # Setup test onboarding script and folder
    @omsadmin_test_dir = `#{@prep_omsadmin} #{@base_dir} #{@ruby_test_dir}`.strip()
    assert_equal(0, $?.to_i, "Unexpected failure setting up the test")
  end
  
  def do_onboard
    omsadmin_script = "#{@omsadmin_test_dir}/omsadmin.sh"
    onboard_out = `#{omsadmin_script} -w #{TEST_WORKSPACE_ID} -s #{TEST_SHARED_KEY}`
    assert_equal(0, $?.to_i, "Unexpected failure onboarding : '#{onboard_out}'")
  end

  def test_send_data
    # Make sure that we read test onboarding information from the environment varibles
    assert(TEST_WORKSPACE_ID != nil, "TEST_WORKSPACE_ID should be set by the environment for this test to run.") 
    assert(TEST_SHARED_KEY != nil, "TEST_SHARED_KEY should be set by the environment for this test to run.")

    assert(TEST_WORKSPACE_ID.empty? == false, "TEST_WORKSPACE_ID should not be empty.") 
    assert(TEST_SHARED_KEY.empty? == false, "TEST_SHARED_KEY should not be empty.")

    # Onboard to create cert and key
    prep_onboard
    do_onboard
    
    # Mock the configuration
    conf_path = "#{@omsadmin_test_dir}/omsadmin.conf"
    cert_path = "#{@omsadmin_test_dir}/oms.crt"
    key_path = "#{@omsadmin_test_dir}/oms.key"

    conf = %[
      omsadmin_conf_path #{conf_path}
      cert_path #{cert_path}
      key_path #{key_path}
    ]
    tag = 'test'
    d = Fluent::Test::OutputTestDriver.new(Fluent::OutputOMSApi, tag).configure(conf)
    success = OMS::Configuration.load_configuration(conf_path, cert_path, key_path)
    assert_equal(true, success, "Configuration should be loaded")

    output = d.instance
    output.start

    # Mock data
    tag = "oms.api.LinuxRestApiTest"
    records = [
    {
      'id'=> 1,
      'ts'=> "#{Time.now.utc}", 
      'msg'=> 'Message 1' 
    },
    {
      'id'=> 2,
      'ts'=> "#{Time.now.utc}",
      'msg'=> 'Message 2'
    }]

    assert_nothing_raised(RuntimeError, "Failed to send data to api : '#{$log.logs}'") do
      output.handle_records(tag, records)
    end

    assert_equal(0, $log.logs.length, "No exception should be logged, but '#{$log.logs}'")

    $log.clear
    time = Time.now.utc
    tag = "oms.api"
    assert_nothing_raised(RuntimeError, "Failed to send data to api : '#{$log.logs}'") do
      output.handle_records(tag, records)
    end

    assert_not_equal(0, $log.logs.length, "Expect error in log, but nothing")
    assert($log.logs[-1].include?("The tag does not have at least 3 parts"), "Expect error in log, but: '#{$log.logs}'")

    $log.clear
    time = Time.now.utc
    tag = "oms.api.1abc"
    assert_nothing_raised(RuntimeError, "Failed to send data to api : '#{$log.logs}'") do
      output.handle_records(tag, records)
    end

    assert_not_equal(0, $log.logs.length, "Expect error in log, but nothing")
    assert($log.logs[-1].include?("The log type '1abc' is not valid"), "Expect error in log, but: '#{$log.logs}'")
  end

end
