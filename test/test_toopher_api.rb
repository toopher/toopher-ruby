require 'rubygems'
require 'test/unit'
require 'webmock/test_unit'
require 'toopher_api'
require 'uuidtools'
require 'fastimage'
require 'time'
require 'mocha/test_unit'

class TestToopherIframe < Test::Unit::TestCase
  def setup
    @request_token = 's9s7vsb'
    @iframe_api = ToopherIframe.new('abcdefg', 'hijklmnop', { :nonce => '12345678' }, base_url = 'https://api.toopher.test/v1/')
    Time.stubs(:now).returns(Time.at(1000))
    @user = {
        'id' => '1',
        'name' => 'user name',
        'toopher_authentication_enabled' => 'true',
        'toopher_sig' => 'RszgG9QE1rF9t7DVTGg+1I25yHM=',
        'session_token' => @request_token,
        'timestamp' => '1000',
        'resource_type' => 'requester_user'
    }
    @encoded_user = {'toopher_iframe_data' => URI.encode_www_form(@user).encode('utf-8')}
    @pairing = {
        'id' => '1',
        'enabled' => 'true',
        'pending' => 'false',
        'pairing_user_id' => @user['id'],
        'user_name' => @user['name'],
        'user_toopher_authentication_enabled' => @user['toopher_authentication_enabled'],
        'toopher_sig' => 'ucwKhkPpN4VxNbx3dMypWzi4tBg=',
        'session_token' => @request_token,
        'timestamp' => '1000',
        'resource_type' => 'pairing'
    }
    @encoded_pairing = {'toopher_iframe_data' => URI.encode_www_form(@pairing).encode('utf-8')}
    @auth_request = {
        'id' => '1',
        'pending' => 'false',
        'granted' => 'true',
        'automated' => 'false',
        'reason' => 'it is a test',
        'reason_code' => '100',
        'terminal_id' => '1',
        'terminal_name' => 'terminal name',
        'terminal_requester_specified_id' => 'requester specified id',
        'pairing_user_id' => @user['id'],
        'user_name' => @user['name'],
        'user_toopher_authentication_enabled' => @user['toopher_authentication_enabled'],
        'action_id' => '1',
        'action_name' => 'action name',
        'toopher_sig' => 's+fYUtChrNMjES5Xa+755H7BQKE=',
        'session_token' => @request_token,
        'timestamp' => '1000',
        'resource_type' => 'authentication_request'
    }
    @encoded_auth_request = {'toopher_iframe_data' => URI.encode_www_form(@auth_request).encode('utf-8')}
  end

  def test_process_postback_returns_authentication_request
    auth_request = @iframe_api.process_postback(@encoded_auth_request, @request_token)
    assert_kind_of(AuthenticationRequest, auth_request)
    assert(auth_request.id == @auth_request['id'], 'Authentication request id was incorrect')
    assert(auth_request.pending == false, 'Authentication request should not be pending')
    assert(auth_request.granted, 'Authentication request should be granted')
    assert(auth_request.automated == false, 'Authentication request should not be automated')
    assert(auth_request.reason == @auth_request['reason'], 'Authentication request reason was incorrect')
    assert(auth_request.reason_code == @auth_request['reason_code'], 'Authentication request reason code was incorrect')
    assert(auth_request.terminal.id == @auth_request['terminal_id'], 'Terminal id was incorrect')
    assert(auth_request.terminal.name == @auth_request['terminal_name'], 'Terminal name was incorrect')
    assert(auth_request.terminal.requester_specified_id == @auth_request['terminal_requester_specified_id'], 'Terminal requester specified id was incorrect')
    assert(auth_request.user.id == @auth_request['pairing_user_id'], 'User id was incorrect')
    assert(auth_request.user.name == @auth_request['user_name'], 'User name was incorrect')
    assert(auth_request.user.toopher_authentication_enabled, 'User should be toopher authentication enabled')
    assert(auth_request.action.id == @auth_request['action_id'], 'Action id was incorrect')
    assert(auth_request.action.name == @auth_request['action_name'], 'Action name was incorrect')
  end

  def test_process_postback_returns_pairing
    pairing = @iframe_api.process_postback(@encoded_pairing, @request_token)
    assert_kind_of(Pairing, pairing)
    assert(pairing.id == @pairing['id'], 'Pairing id was incorrect')
    assert(pairing.enabled, 'Pairing should be enabled')
    assert(pairing.pending == false, 'Pairing should not be pending')
    assert(pairing.user.id == @pairing['pairing_user_id'], 'User id was incorrect')
    assert(pairing.user.name == @pairing['user_name'], 'User name was incorrect')
    assert(pairing.user.toopher_authentication_enabled, 'User should be toopher authentication enabled')
  end

  def test_process_postback_returns_user
    user = @iframe_api.process_postback(@encoded_user, @request_token)
    assert_kind_of(User, user)
    assert(user.id == @user['id'], 'User id was incorrect')
    assert(user.name == @user['name'], 'User name was incorrect')
    assert(user.toopher_authentication_enabled, 'User should be toopher authentication enabled')
  end

  def test_process_postback_with_extras_returns_authentication_request
    assert_kind_of(AuthenticationRequest, @iframe_api.process_postback(@encoded_auth_request, @request_token, :ttl => 100))
  end

  def test_process_postback_without_request_token_returns_authentication_request
    assert_kind_of(AuthenticationRequest, @iframe_api.process_postback(@encoded_auth_request))
  end

  def test_process_postback_bad_signature_raises_error
    auth_request = @auth_request.clone
    auth_request['toopher_sig'] = 'invalid'
    e = assert_raise SignatureValidationError do
        @iframe_api.process_postback(get_url_encoded_postback_data(auth_request), @request_token)
    end
    assert("Computed signature does not match submitted signature: #{@auth_request['toopher_sig']} vs #{auth_request['toopher_sig']}" == e.message, 'SignatureValidationError message was incorrect')
  end

  def test_process_postback_expired_signature_raises_error
    Time.stubs(:now).returns(Time.at(2000))
    e = assert_raise SignatureValidationError do
        @iframe_api.process_postback(@encoded_auth_request, @request_token)
    end
    assert('TTL expired' == e.message, 'SignatureValidationError message was incorrect')
  end

  def test_process_postback_missing_signature_raises_error
    @auth_request.delete('toopher_sig')
    e = assert_raise SignatureValidationError do
        @iframe_api.process_postback(get_url_encoded_postback_data(@auth_request), @request_token)
    end
    assert('Missing required keys: toopher_sig' == e.message, 'SignatureValidationError message was incorrect')
  end

  def test_process_postback_missing_timestamp_raises_erroor
    @auth_request.delete('timestamp')
    e = assert_raise SignatureValidationError do
        @iframe_api.process_postback(get_url_encoded_postback_data(@auth_request), @request_token)
    end
    assert('Missing required keys: timestamp' == e.message, 'SignatureValidationError message was incorrect')
  end

  def test_process_postback_missing_session_token_raises_error
    @auth_request.delete('session_token')
    e = assert_raise SignatureValidationError do
        @iframe_api.process_postback(get_url_encoded_postback_data(@auth_request), @request_token)
    end
    assert('Missing required keys: session_token' == e.message, 'SignatureValidationError message was incorrect')
  end


  def test_process_postback_invalid_session_token_raises_error
    @auth_request['session_token'] = 'invalid'
    e = assert_raise SignatureValidationError do
        @iframe_api.process_postback(get_url_encoded_postback_data(@auth_request), @request_token)
    end
    assert('Session token does not match expected value!' == e.message, 'SignatureValidationError message was incorrect')
  end

  def test_process_postback_bad_resource_type_raises_error
    @auth_request['resource_type'] = 'invalid'
    @auth_request['toopher_sig'] = 'xEY+oOtJcdMsmTLp6eOy9isO/xQ='
    e = assert_raise ToopherApiError do
        @iframe_api.process_postback(get_url_encoded_postback_data(@auth_request), @request_token)
    end
    assert("The postback resource type is not valid #{@auth_request['resource_type']}" == e.message, 'ToopherApiError message was incorrect')
  end

  def test_process_postback_with_704_raises_user_disabled_error
    @auth_request.merge!({'error_code' => '704', 'error_message' => 'The specified user has disabled Toopher authentication.' })
    e = assert_raise UserDisabledError do
        @iframe_api.process_postback(get_url_encoded_postback_data(@auth_request), @request_token)
    end
    assert("Error code #{@auth_request['error_code']} : #{@auth_request['error_message']}" == e.message, 'UserDisabledError message was incorrect')
  end

  def test_is_authentication_granted_is_true_with_auth_request_granted
    assert(@iframe_api.is_authentication_granted(@encoded_auth_request, @request_token), 'AuthenticationRequest granted should return true')
  end

  def test_is_authentication_granted_is_true_with_auth_request_granted_and_extras
    assert(@iframe_api.is_authentication_granted(@encoded_auth_request, @request_token, :ttl=>100), 'AuthenticationRequest granted with extras should return true')
  end

  def test_is_authentication_granted_is_true_with_auth_request_without_request_token
    assert(@iframe_api.is_authentication_granted(@encoded_auth_request), 'AuthenticationRequest granted without request token should return true')
  end

  def test_is_authentication_granted_is_false_with_auth_request_not_granted
    @auth_request['granted'] = 'false'
    @auth_request['toopher_sig'] = 'nADNKdly9zA2IpczD6gvDumM48I='
    assert(@iframe_api.is_authentication_granted(get_url_encoded_postback_data(@auth_request), @request_token) == false, 'AuthenticationRequest not granted should return false')
  end

  def test_is_authentication_granted_is_false_with_auth_request_granted_and_pending_true
    @auth_request['granted'] = 'true'
    @auth_request['pending'] = 'true'
    @auth_request['toopher_sig'] = 'vmWBQCy8Py5PVkMZRppbCG7cm0w='
    assert(@iframe_api.is_authentication_granted(get_url_encoded_postback_data(@auth_request), @request_token) == false, 'Authentication should not be granted when AuthenticationRequest.granted = true and pending = true')
  end

  def test_is_authentication_granted_is_false_when_pairing_is_returned
    assert(@iframe_api.is_authentication_granted(@encoded_pairing, @request_token) == false, 'Pairing object should return false')
  end

  def test_is_authentication_granted_is_false_when_user_is_returned
    assert(@iframe_api.is_authentication_granted(@encoded_user, @request_token) == false, 'User object should return false')
  end

  def test_is_authentication_granted_is_false_when_signature_validation_error_is_raised
    @auth_request.delete('id')
    assert(@iframe_api.is_authentication_granted(get_url_encoded_postback_data(@auth_request), @request_token) == false, 'SignatureValidationError should return false')
  end

  def test_is_authentication_granted_is_false_when_toopher_api_error_is_raised
    @auth_request.merge!({'resource_type' => 'invalid', 'toopher_sig' => 'xEY+oOtJcdMsmTLp6eOy9isO/xQ='})
    assert(@iframe_api.is_authentication_granted(get_url_encoded_postback_data(@auth_request), @request_token) == false, 'ToopherApiError should return false')
  end

  def test_is_authentication_granted_is_true_when_user_disabled_error_is_raised
    @auth_request.merge!({'error_code' => '704', 'error_message' => 'The specified user has disabled Toopher authentication.' })
    assert(@iframe_api.is_authentication_granted(get_url_encoded_postback_data(@auth_request), @request_token), 'UserDisabledError should return true')
  end

  def test_get_user_management_url_only_username
    expected = 'https://api.toopher.test/v1/web/manage_user?username=jdoe&reset_email=&expires=1300&v=2&oauth_consumer_key=abcdefg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1000&oauth_nonce=12345678&oauth_version=1.0&oauth_signature=SA7CAUj%2B5QcGO%2BMmdPv9ubbaozk%3D'
    user_management_iframe_url = @iframe_api.get_user_management_url('jdoe')
    assert(user_management_iframe_url == expected, 'bad user management url')
  end

  def test_get_user_management_url_with_email_and_extras
    expected = 'https://api.toopher.test/v1/web/manage_user?username=jdoe&reset_email=jdoe%40example.com&expires=1100&v=2&oauth_consumer_key=abcdefg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1000&oauth_nonce=12345678&oauth_version=1.0&oauth_signature=sV8qoKnxJ3fxfP6AHNa0eNFxzJs%3D'
    user_management_iframe_url = @iframe_api.get_user_management_url('jdoe', 'jdoe@example.com', :ttl => 100)
    assert(user_management_iframe_url == expected, 'bad user management url')
  end

  def test_get_user_management_url_with_extras
    expected = 'https://api.toopher.test/v1/web/manage_user?username=jdoe&reset_email=&expires=1100&v=2&oauth_consumer_key=abcdefg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1000&oauth_nonce=12345678&oauth_version=1.0&oauth_signature=CtakenrFTqmVw%2BwPxvrgIM%2BDiwk%3D'
    user_management_iframe_url = @iframe_api.get_user_management_url('jdoe', :ttl => 100)
    assert(user_management_iframe_url == expected, 'bad user management url')
  end

  def test_get_user_management_url_with_email
    expected = 'https://api.toopher.test/v1/web/manage_user?username=jdoe&reset_email=jdoe%40example.com&expires=1300&v=2&oauth_consumer_key=abcdefg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1000&oauth_nonce=12345678&oauth_version=1.0&oauth_signature=NjwH5yWPE2CCJL8v%2FMNknL%2BeTpE%3D'
    user_management_iframe_url = @iframe_api.get_user_management_url('jdoe', 'jdoe@example.com')
    assert(user_management_iframe_url == expected, 'bad user management url')
  end

  def test_get_authentication_url_only_username
    expected = 'https://api.toopher.test/v1/web/authenticate?username=jdoe&reset_email=&action_name=Log+In&session_token=&requester_metadata=&expires=1300&v=2&oauth_consumer_key=abcdefg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1000&oauth_nonce=12345678&oauth_version=1.0&oauth_signature=NkaWUjEPRLwgsQMEJGsIQEpyRT4%3D'
    authentication_url = @iframe_api.get_authentication_url('jdoe')
    assert(authentication_url == expected ,'bad authentication url')
  end

  def test_get_authentication_url_with_optional_args
    expected = 'https://api.toopher.test/v1/web/authenticate?username=jdoe&reset_email=jdoe%40example.com&action_name=it+is+a+test&session_token=s9s7vsb&requester_metadata=metadata&expires=1300&v=2&oauth_consumer_key=abcdefg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1000&oauth_nonce=12345678&oauth_version=1.0&oauth_signature=2TydgMnUwWoiwfpljKpSaFg0Luo%3D'
    authentication_url = @iframe_api.get_authentication_url('jdoe', 'jdoe@example.com', @request_token, 'it is a test', 'metadata')
    assert(authentication_url == expected, 'bad authentication url')
  end

  def test_get_authentication_url_with_optional_args_and_extras
    expected = 'https://api.toopher.test/v1/web/authenticate?username=jdoe&reset_email=jdoe%40example.com&action_name=it+is+a+test&session_token=s9s7vsb&requester_metadata=metadata&allow_inline_pairing=false&automation_allowed=false&challenge_required=true&expires=1100&v=2&oauth_consumer_key=abcdefg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1000&oauth_nonce=12345678&oauth_version=1.0&oauth_signature=61dqeQNPFxNy8PyEFB9e5UfgN8s%3D'
    authentication_url = @iframe_api.get_authentication_url('jdoe', 'jdoe@example.com', @request_token, 'it is a test', 'metadata', :allow_inline_pairing=>false, :automation_allowed=>false, :challenge_required=>true, :ttl => 100)
    assert(authentication_url == expected, 'bad authentication url')
  end

  def test_get_authentication_url_with_extras
    expected = 'https://api.toopher.test/v1/web/authenticate?username=jdoe&reset_email=&action_name=Log+In&session_token=&requester_metadata=&allow_inline_pairing=false&automation_allowed=false&challenge_required=true&expires=1100&v=2&oauth_consumer_key=abcdefg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1000&oauth_nonce=12345678&oauth_version=1.0&oauth_signature=srO3zYEFEEU9od%2Fw0ZjDZzyDUyI%3D'
    authentication_url = @iframe_api.get_authentication_url('jdoe', :allow_inline_pairing=>false, :automation_allowed=>false, :challenge_required=>true, :ttl => 100)
    assert(authentication_url == expected, 'bad authentication url')
  end

  private

  def get_url_encoded_postback_data(data)
      {'toopher_iframe_data' => URI.encode_www_form(data).encode('utf-8')}
  end
end

class TestToopherApi < Test::Unit::TestCase
  def setup
    @api = ToopherApi.new('key', 'secret', { :nonce => 'nonce', :timestamp => '0' }, base_url = 'https://api.toopher.test/v1/')
    @user = {
      :id => UUIDTools::UUID.random_create.to_str,
      :name => 'user',
      :toopher_authentication_enabled => true
    }
    @pairing = {
      :id => UUIDTools::UUID.random_create.to_str,
      :enabled => true,
      :pending => false,
      :user => @user
    }
    @terminal = {
      :id => UUIDTools::UUID.random_create.to_str,
      :name => 'term name',
      :requester_specified_id => 'requester terminal id',
      :user => @user
    }
    @action = {
      :id => UUIDTools::UUID.random_create.to_str,
      :name => 'action name'
    }
    @auth_request = {
      :id => UUIDTools::UUID.random_create.to_str,
      :pending => false,
      :granted => true,
      :automated => true,
      :reason => 'some reason',
      :reason_code => 1,
      :terminal => @terminal,
      :user => @user,
      :action => @action
    }
  end

  def compare_to_default_terminal(actual_terminal)
    assert(actual_terminal.id == @terminal[:id], 'wrong terminal id')
    assert(actual_terminal.name == @terminal[:name], 'wrong terminal name')
    assert(actual_terminal.requester_specified_id == @terminal[:requester_specified_id], 'wrong terminal name extra')
    assert(actual_terminal.user.name == @terminal[:user][:name], 'wrong user name')
    assert(actual_terminal.user.id == @terminal[:user][:id], 'wrong user id')
    assert(actual_terminal.raw_data['user']['name'] == @terminal[:user][:name], 'could not access raw data')
  end

  def compare_to_default_pairing(actual_pairing)
    assert(actual_pairing.id == @pairing[:id], 'bad pairing id')
    assert(actual_pairing.enabled == @pairing[:enabled], 'bad pairing enabled')
    assert(actual_pairing.pending == @pairing[:pending], 'bad pairing pending')
    assert(actual_pairing.user.id == @pairing[:user][:id], 'bad user id')
    assert(actual_pairing.user.name == @pairing[:user][:name], 'bad user name')
    assert(actual_pairing.raw_data['user']['name'] == @pairing[:user][:name], 'could not access raw data')
  end

  def compare_to_default_auth_request(actual_auth_request)
    assert(actual_auth_request.id == @auth_request[:id], 'bad auth id')
    assert(actual_auth_request.pending == @auth_request[:pending], 'bad auth pending')
    assert(actual_auth_request.granted == @auth_request[:granted], 'bad auth granted')
    assert(actual_auth_request.automated == @auth_request[:automated], 'bad auth automated')
    assert(actual_auth_request.reason == @auth_request[:reason], 'bad auth reason')
    assert(actual_auth_request.reason_code == @auth_request[:reason_code], 'bad auth reason code')
    assert(actual_auth_request.terminal.id == @auth_request[:terminal][:id], 'bad auth terminal id')
    assert(actual_auth_request.terminal.name == @auth_request[:terminal][:name], 'bad auth terminal name')
    assert(actual_auth_request.terminal.requester_specified_id == @auth_request[:terminal][:requester_specified_id], 'bad auth terminal name')
    assert(actual_auth_request.action.id == @auth_request[:action][:id], 'bad auth request action id')
    assert(actual_auth_request.action.name == @auth_request[:action][:name], 'bad auth request action id')
    assert(actual_auth_request.raw_data['terminal']['requester_specified_id'] == @auth_request[:terminal][:requester_specified_id], 'bad auth terminal name')
  end

  def test_constructor
    assert_raise ArgumentError do
      api = ToopherApi.new
    end

    assert_raise ArgumentError do
      api = ToopherApi.new('key')
    end

    assert_raise ArgumentError do
      api = ToopherApi.new('', 'secret')
    end

    assert_nothing_raised do
      api = ToopherApi.new('key', 'secret')
    end

  end

  def test_create_pairing_immediate_success
    stub_http_request(:post, "https://api.toopher.test/v1/pairings/create").
      with(
        :body => {
          :pairing_phrase => 'immediate_pair',
          :user_name => @user[:name]
        }
      ).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

      pairing = @api.pair(@user[:name], 'immediate_pair')
      compare_to_default_pairing(pairing)
  end

  def test_create_pairing_with_optional_arg
    stub_http_request(:post, "https://api.toopher.test/v1/pairings/create").
      with(
        :body => {
          :pairing_phrase => 'immediate_pair',
          :user_name => @user[:name],
          :test_param => 'foo'
        }
      ).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

      pairing = @api.pair(@user[:name], 'immediate_pair', :test_param => 'foo')
      compare_to_default_pairing(pairing)
  end

  def test_create_sms_pairing_success
    stub_http_request(:post, "https://api.toopher.test/v1/pairings/create/sms").
      with(
        :body => {
          :user_name => @user[:name],
          :phone_number => '555-555-5555'
        }
      ).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

    pairing = @api.pair(@user[:name], '555-555-5555')
    compare_to_default_pairing(pairing)

    stub_http_request(:post, "https://api.toopher.test/v1/pairings/create/sms").
      with(
        :body => {
          :user_name => @user[:name],
          :phone_number => '555-555-5555',
          :country_code => '1'
        }
      ).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

    pairing = @api.pair(@user[:name], '555-555-5555', :country_code => '1')
    compare_to_default_pairing(pairing)
  end

  def test_create_qr_pairing_success
    stub_http_request(:post, "https://api.toopher.test/v1/pairings/create/qr").
      with(
        :body => {
          :user_name => @user[:name]
        }
      ).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

    pairing = @api.pair(@user[:name])
    compare_to_default_pairing(pairing)
  end

  def test_get_pairing_by_id
    stub_http_request(:get, "https://api.toopher.test/v1/pairings/1").
      to_return(
        :body => {
          :id => '1',
          :enabled => true,
          :pending => false,
          :user => {
            :id => '1',
            :name => 'paired user',
            :toopher_authentication_enabled => true
          }
        }.to_json,
        :status => 200
      )
    stub_http_request(:get, "https://api.toopher.test/v1/pairings/2").
      to_return(
        :body => {
          :id => '2',
          :enabled => false,
          :pending => true,
          :user => {
            :id => '2',
            :name => 'unpaired user',
            :toopher_authentication_enabled => true
          }
        }.to_json,
        :status => 200
      )

      pairing = @api.advanced.pairings.get_by_id('1')
      assert(pairing.id == '1', 'bad pairing id')
      assert(pairing.enabled == true, 'pairing not enabled')
      assert(pairing.pending == false, 'pairing is pending')
      assert(pairing.user.id == '1', 'bad user id')
      assert(pairing.user.name == 'paired user', 'bad user name')

      pairing = @api.advanced.pairings.get_by_id('2')
      assert(pairing.id == '2', 'bad pairing id')
      assert(pairing.enabled == false, 'pairing should not be enabled')
      assert(pairing.pending == true, 'pairing is not pending')
      assert(pairing.user.id == '2', 'bad user id')
      assert(pairing.user.name == 'unpaired user', 'bad user name')
  end

  def test_create_authentication_with_no_action
    stub_http_request(:post, "https://api.toopher.test/v1/authentication_requests/initiate").
      with(
        :body => {
          :pairing_id => @pairing[:id],
          :terminal_name => @terminal[:name]
        }
      ).
      to_return(
        :body => @auth_request.to_json,
        :status => 200
      )

    auth_request = @api.authenticate(@pairing[:id], @terminal[:name])
    compare_to_default_auth_request(auth_request)
  end

  def test_create_authentication_with_optional_arg
    stub_http_request(:post, "https://api.toopher.test/v1/authentication_requests/initiate").
      with(
        :body => {
          :pairing_id => @auth_request[:id],
          :terminal_name => @terminal[:name],
          :test_param => 'foo'
        }
      ).
      to_return(
        :body => @auth_request.to_json,
        :status => 200
      )

    auth_request = @api.authenticate(@auth_request[:id], @terminal[:name], :test_param => 'foo')
    compare_to_default_auth_request(auth_request)
  end

  def test_create_authentication_with_username
    stub_http_request(:post, "https://api.toopher.test/v1/authentication_requests/initiate").
      with(
        :body => {
          :user_name => @user[:name],
          :requester_specified_terminal_id => @terminal[:requester_specified_id]
        }
      ).
      to_return(
        :body => @auth_request.to_json,
        :status => 200
      )

    auth_request = @api.authenticate(@user[:name], @terminal[:requester_specified_id])
    compare_to_default_auth_request(auth_request)
  end

  def test_get_authentication_request_by_id
    stub_http_request(:get, "https://api.toopher.test/v1/authentication_requests/" + @auth_request[:id]).
      to_return(
        :body => @auth_request.to_json,
        :status => 200
      )

    auth_request = @api.advanced.authentication_requests.get_by_id(@auth_request[:id])
    compare_to_default_auth_request(auth_request)
  end

  def test_create_user_terminal
    stub_http_request(:post, 'https://api.toopher.test/v1/user_terminals/create').
      with(
        :body => {
          :user_name => @user[:name],
          :name => @terminal[:name],
          :requester_specified_id => @terminal[:requester_specified_id]
        }
      ).
      to_return(
        :body => @terminal.to_json,
        :status => 200
      )

    terminal = @api.advanced.user_terminals.create(@user[:name], @terminal[:name], @terminal[:requester_specified_id])
    compare_to_default_terminal(terminal)
  end

  def test_get_user_terminal_by_id
    stub_http_request(:get, 'https://api.toopher.test/v1/user_terminals/' + @terminal[:id]).
      to_return(
        :body => @terminal.to_json,
        :status => 200
      )

    terminal = @api.advanced.user_terminals.get_by_id(@terminal[:id])
    compare_to_default_terminal(terminal)
  end

  def test_create_user
    stub_http_request(:post, 'https://api.toopher.test/v1/users/create').
      with(
        :body => {
          :name => @user[:name]
        }
      ).
      to_return(
        :body => @user.to_json,
        :status => 200
      )

    user = @api.advanced.users.create(@user[:name])
    assert(user.id == @user[:id], 'wrong user id')
    assert(user.name == @user[:name], 'wrong user name')
    assert(user.toopher_authentication_enabled == @user[:toopher_authentication_enabled], 'wrong user disabled status')
  end

  def test_get_user_by_id
    stub_http_request(:get, 'https://api.toopher.test/v1/users/' + @user[:id]).
      to_return(
        :body => @user.to_json,
        :status => 200
      )

    user = @api.advanced.users.get_by_id(@user[:id])
    assert(user.id == @user[:id], 'wrong user id')
    assert(user.name == @user[:name], 'wrong user name')
    assert(user.toopher_authentication_enabled == @user[:toopher_authentication_enabled], 'wrong user disabled status')
  end

  def test_get_user_by_name
    stub_http_request(:get, 'https://api.toopher.test/v1/users?name=' + @user[:name]).
      to_return(
        :body => [
          {
            :requester => {
              :name => 'toopher.test',
              :id => 'requester1'
            },
            :id => @user[:id],
            :name => @user[:name],
            :toopher_authentication_enabled => @user[:toopher_authentication_enabled]
          }
        ].to_json
      )

    user = @api.advanced.users.get_by_name(@user[:name])
    assert(user.id == @user[:id], 'bad user id')
    assert(user.name == @user[:name], 'bad user name')
    assert(user.toopher_authentication_enabled == @user[:toopher_authentication_enabled], 'bad user disabled status')
  end

  def test_no_user_to_get_by_name_raises_correct_error
    stub_http_request(:get, 'https://api.toopher.test/v1/users?name=' + @user[:name]).
      to_return(
        :body => '[]',
        :status => 200
      )
    assert_raise ToopherApiError do
      user = @api.advanced.users.get_by_name(@user[:name])
    end
  end

  def test_multiple_users_to_get_by_name_raises_correct_error
    stub_http_request(:get, 'https://api.toopher.test/v1/users?name=' + @user[:name]).
      to_return(
        :body => [
          {
            :requester => {
              :name => 'toopher.test',
              :id => 'requester1'
            },
            :id => 'ser1',
            :name => 'user',
            :toopher_authentication_enabled => true
          },
          {
            :requester => {
              :name => 'toopher.test',
              :id => 'requester1',
            },
            :id => 'user2',
            :name => 'user',
            :toopher_authentication_enabled => true
          }
        ].to_json,
        :status => 200
      )
    assert_raise ToopherApiError do
      user = @api.advanced.users.get_by_name(@user[:name])
    end
  end

  def test_get
    stub_http_request(:get, 'https://api.toopher.test/v1/pairings/' + @pairing[:id]).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

    result = @api.advanced.raw.get('pairings/' + @pairing[:id])
    assert(result['id'] == @pairing[:id], 'wrong pairing id')
    assert(result['enabled'] == @pairing[:enabled], 'pairing should be enabled')
    assert(result['pending'] == @pairing[:pending], 'pairing should not be pending')
    assert(result['user']['id'] == @pairing[:user][:id], 'wrong user id')
    assert(result['user']['name'] == @pairing[:user][:name], 'wrong user name')
  end

  def test_post
    stub_http_request(:post, 'https://api.toopher.test/v1/user_terminals/create').
      with(
        :body => {
          :name => @terminal[:name],
          :requester_specified_id => @terminal[:requester_specified_id],
          :user_name => @terminal[:user][:name]
        }
      ).
      to_return(
        :body => @terminal.to_json,
        :status => 200
      )

    result = @api.advanced.raw.post('user_terminals/create', :name => @terminal[:name], :requester_specified_id => @terminal[:requester_specified_id], :user_name => @terminal[:user][:name])
    assert(result['id'] == @terminal[:id], 'wrong terminal id')
    assert(result['name'] == @terminal[:name], 'wrong terminal name')
    assert(result['requester_specified_id'] == @terminal[:requester_specified_id], 'wrong terminal name extra')
    assert(result['user']['id'] == @terminal[:user][:id], 'wrong user id')
    assert(result['user']['name'] == @terminal[:user][:name], 'wrong user name')
  end

  def test_toopher_request_error
    stub_http_request(:get, "https://api.toopher.test/v1/authentication_requests/1").
      to_return(
        :body => {
          :error_code => 401,
          :error_message => 'Not a valid OAuth signed request'
        }.to_json,
        :status => 401
      )
    assert_raise ToopherApiError do
      auth = @api.advanced.authentication_requests.get_by_id('1')
    end
  end

  def test_disabled_user_raises_correct_error
    stub_http_request(:post, "https://api.toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => {
          :error_code => 704,
          :error_message => 'disabled user'
        }.to_json,
        :status => 409
      )
    assert_raise UserDisabledError do
      auth_request = @api.authenticate('disabled user', 'terminal name')
    end
  end

  def test_unknown_user_raises_correct_error
    stub_http_request(:post, "https://api.toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => {
          :error_code => 705,
          :error_message => 'disabled user'
        }.to_json,
        :status => 409
      )
    assert_raise UnknownUserError do
      auth_request = @api.authenticate('unknown user', 'terminal name')
    end
  end

  def test_unknown_terminal_raises_correct_error
    stub_http_request(:post, "https://api.toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => {
          :error_code => 706,
          :error_message => 'unknown terminal'
        }.to_json,
        :status => 409
      )
    assert_raise UnknownTerminalError do
      auth_request = @api.authenticate('user', 'unknown terminal name')
    end
  end

  def test_disabled_pairing_raises_correct_error
    stub_http_request(:post, "https://api.toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => {
          :error_code => 601,
          :error_message => 'pairing has been deactivated'
        }.to_json,
        :status => 601
      )
    assert_raise PairingDeactivatedError do
      auth_request = @api.authenticate('user', 'terminal name')
    end
  end

  def test_unauthorized_pairing_raises_correct_error
    stub_http_request(:post, "https://api.toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => {
          :error_code => 601,
          :error_message => 'pairing has not been authorized'
        }.to_json,
        :status => 601
      )
    assert_raise PairingDeactivatedError do
      auth_request = @api.authenticate('user', 'terminal name')
    end
  end

  def test_version_string_exists
    major, minor, patch = ToopherApi::VERSION.split('.')
    assert(major >= '1', 'version string (major level) is invalid')
    assert(minor >= '0', 'version string (minor level) is invalid')
    assert(patch >= '0', 'version string (patch level) is invalid')
    assert(ToopherApi::VERSION >= '1.0.6', 'version string does not exist')
  end

  def test_gemspec_version_matches_version_string
    version_string = File.open('toopher_api.gemspec').grep(/version/).first
    gemspec_version = /version\s+=\s+'([\d.]+)'/.match(version_string).captures.first
    assert(ToopherApi::VERSION == gemspec_version, "version strings do not match: library = #{ToopherApi::VERSION} and gemspec = #{gemspec_version}")
  end
end

class TestPairing < Test::Unit::TestCase
  def setup
    @api = ToopherApi.new('key', 'secret', { :nonce => 'nonce', :timestamp => '0' }, base_url = 'https://api.toopher.test/v1/')
    @user = {
      'id' => UUIDTools::UUID.random_create.to_str,
      'name' => 'user',
      'toopher_authentication_enabled' => true
    }
    @pairing = {
      'id' => UUIDTools::UUID.random_create.to_str,
      'enabled' => true,
      'pending' => false,
      'user' => @user
    }
  end

  def test_constructor
    assert_nothing_raised do
      pairing = Pairing.new(@pairing, @api)

      assert(pairing.id == @pairing['id'], 'bad pairing id')
      assert(pairing.enabled == @pairing['enabled'], 'pairing should not be enabled')
      assert(pairing.pending == @pairing['pending'], 'pairing should be pending')
      assert(pairing.user.id == @pairing['user']['id'], 'bad user id')
      assert(pairing.user.name == @pairing['user']['name'], 'bad user name')
    end
  end

  def test_refresh_from_server
    pairing = Pairing.new(@pairing, @api)

    stub_http_request(:get, 'https://api.toopher.test/v1/pairings/' + @pairing['id']).
      to_return(
        :body => {
          :id => @pairing['id'],
          :enabled => false,
          :pending => true,
          :user => {
            :id => @pairing['user']['id'],
            :name => 'paired user changed name',
            :toopher_authentication_enabled => true
          }
        }.to_json,
        :status => 200
      )

    pairing.refresh_from_server
    assert(pairing.id == @pairing['id'], 'bad pairing id')
    assert(pairing.enabled == false, 'pairing not enabled')
    assert(pairing.pending == true, 'pairing is pending')
    assert(pairing.user.id == @pairing['user']['id'], 'bad user id')
    assert(pairing.user.name == 'paired user changed name', 'bad user name')
  end

  def test_get_reset_link
    stub_http_request(:get, 'https://api.toopher.test/v1/pairings/' + @pairing['id']).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

    stub_http_request(:post,'https://api.toopher.test/v1/pairings/' + @pairing['id'] + '/generate_reset_link').
      to_return(
        :body => {
          :url => 'http://api.toopher.test/v1/pairings/' + @pairing['id'] + '/reset?reset_authorization=abcde'
        }.to_json,
        :status => 200
      )
    pairing = @api.advanced.pairings.get_by_id(@pairing['id'])
    reset_link = pairing.get_reset_link
    assert(reset_link == 'http://api.toopher.test/v1/pairings/' + @pairing['id'] + '/reset?reset_authorization=abcde')
  end

  def test_email_reset_link_to_user
    stub_http_request(:get, 'https://api.toopher.test/v1/pairings/' + @pairing['id']).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

    stub_http_request(:post, 'https://api.toopher.test/v1/pairings/' + @pairing['id'] + '/send_reset_link').
      with(
        :body => {
          :reset_email => 'email'
        }
      ).
      to_return(
        :body => '[]',
        :status => 201
      )
    pairing = @api.advanced.pairings.get_by_id(@pairing['id'])
    assert_nothing_raised do
      pairing.email_reset_link_to_user('email')
    end
  end

  def test_get_qr_code_image
    pairing = Pairing.new(@pairing, @api)
    File.open('qr_image.png', 'rb') do |qr_image|
      stub_http_request(:get, 'https://api.toopher.test/v1/qr/pairings/' + @pairing['id']).
        to_return(
          :body => qr_image.read,
          :status => 200
        )

      qr_image_data = pairing.get_qr_code_image
      File.open('new_image.png', 'wb') do |new_image|
        new_image.write(qr_image_data)
      end
      file_type = FastImage.type('new_image.png')
      assert(file_type == :png)
    end
  end
end

class TestAuthenticationRequest < Test::Unit::TestCase
  def setup
    @api = ToopherApi.new('key', 'secret', { :nonce => 'nonce', :timestamp => '0' }, base_url = 'https://api.toopher.test/v1/')
    @user = {
      'id' => UUIDTools::UUID.random_create.to_str,
      'name' => 'user',
      'toopher_authentication_enabled' => true
    }
    @terminal = {
      'id' => UUIDTools::UUID.random_create.to_str,
      'name' => 'term name',
      'requester_specified_id' => 'requester terminal id',
      'user' => @user
    }
    @action = {
      'id' => UUIDTools::UUID.random_create.to_str,
      'name' => 'action name'
    }
    @auth_request = {
      'id' => UUIDTools::UUID.random_create.to_str,
      'pending' => false,
      'granted' => true,
      'automated' => true,
      'reason' => 'some reason',
      'reason_code' => 1,
      'terminal' => @terminal,
      'user' => @user,
      'action' => @action
    }
  end

  def test_constructor
    assert_nothing_raised do
      auth_request = AuthenticationRequest.new(@auth_request, @api)

      assert(auth_request.id == @auth_request['id'], 'bad auth request id')
      assert(auth_request.pending == @auth_request['pending'], 'bad auth_request pending status')
      assert(auth_request.granted == @auth_request['granted'], 'bad auth_request granted status')
      assert(auth_request.automated == @auth_request['automated'], 'bad auth_request automated status')
      assert(auth_request.reason == @auth_request['reason'], 'bad auth_request reason')
      assert(auth_request.reason_code == @auth_request['reason_code'], 'bad auth_request reason code')
      assert(auth_request.terminal.id == @auth_request['terminal']['id'], 'bad terminal id')
      assert(auth_request.terminal.name == @auth_request['terminal']['name'], 'bad terminal name')
      assert(auth_request.terminal.requester_specified_id == @auth_request['terminal']['requester_specified_id'], 'bad terminal name extra')
      assert(auth_request.user.id == @auth_request['user']['id'], 'bad user id')
      assert(auth_request.user.name == @auth_request['user']['name'], 'bad user name')
      assert(auth_request.action.id == @auth_request['action']['id'], 'bad auth request action id')
      assert(auth_request.action.name == @auth_request['action']['name'], 'bad auth request action name')
      assert(auth_request.user.toopher_authentication_enabled == @auth_request['user']['toopher_authentication_enabled'], 'bad user disabled status')
    end
  end

  def test_refresh_from_server
    auth_request = AuthenticationRequest.new(@auth_request, @api)

    stub_http_request(:get, 'https://api.toopher.test/v1/authentication_requests/' + @auth_request['id']).
      to_return(
        :body => {
          :id => @auth_request['id'],
          :pending => false,
          :granted => true,
          :automated => true,
          :reason => 'reason has changed',
          :reason_code => 2,
          :terminal => {
            :id => @auth_request['terminal']['id'],
            :name => 'term name changed',
            :requester_specified_id => @auth_request['terminal']['requester_specified_id'],
            :user => @auth_request['terminal']['user']
          },
          :user => @auth_request['terminal']['user'],
          :action => {
            :id => @auth_request['action']['id'],
            :name => 'action name changed'
          }
        }.to_json,
        :status => 200
      )
    auth_request.refresh_from_server
    assert(auth_request.id == @auth_request['id'], 'bad auth request id')
    assert(auth_request.pending == false, 'auth request should not be pending')
    assert(auth_request.granted == true, 'auth request should be granted')
    assert(auth_request.automated == true, 'auth request should be automated')
    assert(auth_request.reason == 'reason has changed', 'bad auth request reason')
    assert(auth_request.reason_code == 2, 'bad auth request reason code')
    assert(auth_request.terminal.id == @auth_request['terminal']['id'], 'bad terminal id')
    assert(auth_request.terminal.name == 'term name changed', 'bad terminal name')
    assert(auth_request.terminal.requester_specified_id == @auth_request['terminal']['requester_specified_id'], 'bad terminal name extra')
    assert(auth_request.action.id == @auth_request['action']['id'], 'bad auth request action id')
    assert(auth_request.action.name == 'action name changed', 'bad auth request action name')
  end

  def test_authenticate_with_otp
    auth_request = AuthenticationRequest.new(@auth_request, @api)

    stub_http_request(:post, 'https://api.toopher.test/v1/authentication_requests/' + @auth_request['id'] + '/otp_auth').
      with(
        :body => { :otp => 'otp' }
      ).
      to_return(
        :body => {
          :id => @auth_request['id'],
          :pending => false,
          :granted => true,
          :automated => true,
          :reason => 'it is a test',
          :reason_code => 3,
          :terminal => {
            :id => @auth_request['terminal']['id'],
            :name => 'term name',
            :requester_specified_id => @auth_request['terminal']['requester_specified_id'],
            :user => @auth_request['terminal']['user']
          },
          :user => @auth_request['terminal']['user'],
          :action => @auth_request['action']
        }.to_json,
        :status => 200
      )

    auth_request.grant_with_otp('otp')
    assert(auth_request.id == @auth_request['id'], 'bad auth request id')
    assert(auth_request.pending == false, 'auth request should not be pending')
    assert(auth_request.granted == true, 'auth request should be granted')
    assert(auth_request.automated == true, 'auth request should be automated')
    assert(auth_request.reason == 'it is a test', 'bad auth request reason')
    assert(auth_request.reason_code == 3, 'bad auth request reason code')
    assert(auth_request.terminal.id == @auth_request['terminal']['id'], 'bad terminal id')
    assert(auth_request.terminal.name == 'term name', 'bad terminal name')
    assert(auth_request.terminal.requester_specified_id == @auth_request['terminal']['requester_specified_id'], 'bad terminal name extra')
  end
end

class TestUserTerminal < Test::Unit::TestCase
  def setup
    @api = ToopherApi.new('key', 'secret', { :nonce => 'nonce', :timestamp => '0' }, base_url = 'https://api.toopher.test/v1/')
    @user = {
      'id' => UUIDTools::UUID.random_create.to_str,
      'name' => 'user',
      'toopher_authentication_enabled' => true
    }
    @terminal = {
      'id' => UUIDTools::UUID.random_create.to_str,
      'name' => 'term name',
      'requester_specified_id' => 'requester terminal id',
      'user' => @user
    }
  end

  def test_constructor
    assert_nothing_raised do
      terminal = UserTerminal.new(@terminal, @api)

      assert(terminal.id == @terminal['id'], 'bad terminal id')
      assert(terminal.name == @terminal['name'], 'bad terminal name')
      assert(terminal.requester_specified_id == @terminal['requester_specified_id'], 'bad terminal name extra')
      assert(terminal.user.id == @terminal['user']['id'], 'bad user id')
      assert(terminal.user.name == @terminal['user']['name'], 'bad user name')
    end
  end

  def test_refresh_from_server
    terminal = UserTerminal.new(@terminal, @api)

    stub_http_request(:get, 'https://api.toopher.test/v1/user_terminals/' + @terminal['id']).
      to_return(
        :body => {
          :id => @terminal['id'],
          :name => 'term name changed',
          :requester_specified_id => @terminal['requester_specified_id'],
          :user => {
            :id => @terminal['user']['id'],
            :name => 'user name changed',
            :toopher_authentication_enabled => true
          }
        }.to_json,
        :status => 200
      )

    terminal.refresh_from_server
    assert(terminal.id == @terminal['id'], 'bad terminal id')
    assert(terminal.name == 'term name changed', 'bad terminal name')
    assert(terminal.requester_specified_id == @terminal['requester_specified_id'], 'bad terminal name extra')
    assert(terminal.user.id == @terminal['user']['id'], 'bad user id')
    assert(terminal.user.name == 'user name changed', 'bad user name')
  end
end

class TestUser < Test::Unit::TestCase
  def setup
    @api = ToopherApi.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://api.toopher.test/v1/")
    @user = {
      'id' => UUIDTools::UUID.random_create.to_str,
      'name' => 'user name',
      'toopher_authentication_enabled' => false
    }
  end

  def test_constructor
    assert_nothing_raised do
      user = User.new(@user, @api)

      assert(user.id == @user['id'], 'bad user id')
      assert(user.name == @user['name'], 'bad user name')
      assert(user.toopher_authentication_enabled == @user['toopher_authentication_enabled'], 'user should be enabled')
    end
  end

  def test_refresh_from_server
    user = User.new(@user, @api)

    stub_http_request(:get, 'https://api.toopher.test/v1/users/' + @user['id']).
      to_return(
        :body => {
          :id => @user['id'],
          :name => 'user name changed',
          :toopher_authentication_enabled => false
        }.to_json,
        :status => 200
      )

    user.refresh_from_server
    assert(user.id == @user['id'], 'bad user id')
    assert(user.name == 'user name changed', 'bad user name')
    assert(user.toopher_authentication_enabled == false, 'user should be disabled')
  end

  def test_enable_toopher_authentication
    user = User.new(@user, @api)

    stub_http_request(:post, 'https://api.toopher.test/v1/users/' + @user['id']).
      with(
        :body => { :toopher_authentication_enabled => 'true' }
      ).
      to_return(
        :body => {
          :id => @user['id'],
          :name => @user['name'],
          :toopher_authentication_enabled => true
        }.to_json,
        :status => 200
      )

    user.enable_toopher_authentication
    assert(user.toopher_authentication_enabled == true, 'user should be enabled')
  end

  def test_disable_toopher_authentication
    user = User.new(@user, @api)

    stub_http_request(:post, 'https://api.toopher.test/v1/users/' + @user['id']).
      with(
        :body => { :toopher_authentication_enabled => 'false' }
      ).
      to_return(
        :body => {
          :id => @user['id'],
          :name => @user['name'],
          :toopher_authentication_enabled => false
        }.to_json,
        :status => 200
      )

    user.disable_toopher_authentication
    assert(user.toopher_authentication_enabled == false, 'user should be enabled')
  end

  def test_reset_user
    user = User.new(@user, @api)

    stub_http_request(:post, 'https://api.toopher.test/v1/users/reset').
      with(
        :body => { :name => @user['name'] }
      ).
      to_return(
        :body => '[]',
        :status => 200
      )

    result = user.reset
    assert(result == true)
  end
end
