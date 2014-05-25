require 'rubygems'
require 'test/unit'
require 'webmock/test_unit'
require 'toopher_api'
require 'coveralls'

Coveralls.wear!

class TestToopher < Test::Unit::TestCase
  def test_constructor()

    assert_raise ArgumentError do
      api = ToopherAPI.new
    end

    assert_raise ArgumentError do
      api = ToopherAPI.new('key')
    end

    assert_raise ArgumentError do
      api = ToopherAPI.new('', 'secret')
    end

    assert_nothing_raised do
      api = ToopherAPI.new('key', 'secret')
    end

  end

  def test_create_pairing_immediate_success()
    stub_http_request(:post, "https://toopher.test/v1/pairings/create").
      with(
#        :headers => {
#          'Authorization' => 'OAuth oauth_consumer_key="key",oauth_nonce="nonce",oauth_signature="%2FW9rUAFDuJTTBtfSxeQ%2FDxWpVQY%3D",oauth_signature_method="HMAC-SHA1",oauth_timestamp="0",oauth_version="1.0"'
#          },
        :body => { 'pairing_phrase' => 'immediate_pair', 'user_name' => 'user' }
      ).
      to_return(
        :body => '{"id":"1","enabled":true,"user":{"id":"1","name":"user"}}',
        :status => 200
      )

      toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
      pairing = toopher.pair('immediate_pair', 'user')
      assert(pairing.id == '1', 'bad pairing id')
      assert(pairing.enabled == true, 'pairing not enabled')
      assert(pairing.user_id == '1', 'bad user id')
      assert(pairing.user_name == 'user', 'bad user name')
      assert(pairing.raw['user']['name'] == 'user', 'could not access raw data')
  end

  def test_create_pairing_with_optional_arg()
    stub_http_request(:post, "https://toopher.test/v1/pairings/create").
      with(
        :body => { 'pairing_phrase' => 'immediate_pair', 'user_name' => 'user' , 'test_param' => 'foo'}
      ).
      to_return(
        :body => '{"id":"1","enabled":true,"user":{"id":"1","name":"user"}}',
        :status => 200
      )

      toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
      pairing = toopher.pair('immediate_pair', 'user', :test_param => 'foo')
      assert(pairing.id == '1', 'bad pairing id')
      assert(pairing.enabled == true, 'pairing not enabled')
      assert(pairing.user_id == '1', 'bad user id')
      assert(pairing.user_name == 'user', 'bad user name')
  end

  def test_get_pairing_status()
    stub_http_request(:get, "https://toopher.test/v1/pairings/1").
      to_return(
        :body => '{"id":"1","enabled":true,"user":{"id":"1","name":"paired user"}}',
        :status => 200
      )
    stub_http_request(:get, "https://toopher.test/v1/pairings/2").
      to_return(
        :body => '{"id":"2","enabled":false,"user":{"id":"2","name":"unpaired user"}}',
        :status => 200
      )

      toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
      pairing = toopher.get_pairing_status('1')
      assert(pairing.id == '1', 'bad pairing id')
      assert(pairing.enabled == true, 'pairing not enabled')
      assert(pairing.user_id == '1', 'bad user id')
      assert(pairing.user_name == 'paired user', 'bad user name')

      pairing = toopher.get_pairing_status('2')
      assert(pairing.id == '2', 'bad pairing id')
      assert(pairing.enabled == false, 'pairing should not be enabled')
      assert(pairing.user_id == '2', 'bad user id')
      assert(pairing.user_name == 'unpaired user', 'bad user name')
  end

  def test_create_authentication_with_no_action()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      with(
        :body => { 'pairing_id' => '1', 'terminal_name' => 'term name' }
      ).
      to_return(
        :body => '{"id":"1","pending":false,"granted":true,"automated":true,"reason":"some reason","terminal":{"id":"1","name":"term name"}}',
        :status => 200
      )

    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    auth = toopher.authenticate('1', 'term name')
    assert(auth.id == '1', 'wrong auth id')
    assert(auth.pending == false, 'wrong auth pending')
    assert(auth.granted == true, 'wrong auth granted')
    assert(auth.automated == true, 'wrong auth automated')
    assert(auth.reason == 'some reason', 'wrong auth reason')
    assert(auth.terminal_id == '1', 'wrong auth terminal id')
    assert(auth.terminal_name == 'term name', 'wrong auth terminal name')
  end

  def test_create_authentication_with_optional_arg()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      with(
        :body => { 'pairing_id' => '1', 'terminal_name' => 'term name', 'test_param' => 'foo' }
      ).
      to_return(
        :body => '{"id":"1","pending":false,"granted":true,"automated":true,"reason":"some reason","terminal":{"id":"1","name":"term name"}}',
        :status => 200
      )

    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    auth = toopher.authenticate('1', 'term name', '', {'test_param' => 'foo'})
    assert(auth.id == '1', 'wrong auth id')
    assert(auth.pending == false, 'wrong auth pending')
    assert(auth.granted == true, 'wrong auth granted')
    assert(auth.automated == true, 'wrong auth automated')
    assert(auth.reason == 'some reason', 'wrong auth reason')
    assert(auth.terminal_id == '1', 'wrong auth terminal id')
    assert(auth.terminal_name == 'term name', 'wrong auth terminal name')
  end

  def test_get_authentication_status()
    stub_http_request(:get, "https://toopher.test/v1/authentication_requests/1").
      to_return(
        :body => '{"id":"1","pending":false,"granted":true,"automated":true,"reason":"some reason","terminal":{"id":"1","name":"term name"}}',
        :status => 200
      )
    stub_http_request(:get, "https://toopher.test/v1/authentication_requests/2").
      to_return(
        :body => '{"id":"2","pending":true,"granted":false,"automated":false,"reason":"some other reason","terminal":{"id":"2","name":"another term name"}}',
        :status => 200
      )

    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    auth = toopher.get_authentication_status('1')
    assert(auth.id == '1', 'wrong auth id')
    assert(auth.pending == false, 'wrong auth pending')
    assert(auth.granted == true, 'wrong auth granted')
    assert(auth.automated == true, 'wrong auth automated')
    assert(auth.reason == 'some reason', 'wrong auth reason')
    assert(auth.terminal_id == '1', 'wrong auth terminal id')
    assert(auth.terminal_name == 'term name', 'wrong auth terminal name')
    assert(auth.raw['terminal']['name'] == 'term name', 'could not access raw data')

    auth = toopher.get_authentication_status('2')
    assert(auth.id == '2', 'wrong auth id')
    assert(auth.pending == true, 'wrong auth pending')
    assert(auth.granted == false, 'wrong auth granted')
    assert(auth.automated == false, 'wrong auth automated')
    assert(auth.reason == 'some other reason', 'wrong auth reason')
    assert(auth.terminal_id == '2', 'wrong auth terminal id')
    assert(auth.terminal_name == 'another term name', 'wrong auth terminal name')
    assert(auth.raw['terminal']['name'] == 'another term name', 'could not access raw data')
  end

  def test_toopher_request_error()
    stub_http_request(:get, "https://toopher.test/v1/authentication_requests/1").
      to_return(
        :body => '{"error_code":401,"error_message":"Not a valid OAuth signed request"}',
        :status => 401
      )
    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    assert_raise ToopherApiError do
      auth = toopher.get_authentication_status('1')
    end
  end

  def test_disabled_user_raises_correct_error()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => '{"error_code":704,"error_message":"disabled user"}',
        :status => 409
      )
    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    assert_raise UserDisabledError do
      auth_request = toopher.authenticate_by_user_name('disabled user', 'terminal name')
    end
  end

  def test_unknown_user_raises_correct_error()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => '{"error_code":705,"error_message":"disabled user"}',
        :status => 409
      )
    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    assert_raise UnknownUserError do
      auth_request = toopher.authenticate_by_user_name('unknown user', 'terminal name')
    end
  end

  def test_unknown_terminal_raises_correct_error()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => '{"error_code":706, "error_message":"unknown terminal"}',
        :status => 409
      )
    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    assert_raise UnknownTerminalError do
      auth_request = toopher.authenticate_by_user_name('user', 'unknown terminal name')
    end
  end

  def test_disabled_pairing_raises_correct_error()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => '{"error_code":601, "error_message":"pairing has been deactivated"}',
        :status => 601
      )
    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    assert_raise PairingDeactivatedError do
      auth_request = toopher.authenticate_by_user_name('user', 'terminal name')
    end
  end

  def test_unauthorized_pairing_raises_correct_error()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => '{"error_code":601, "error_message":"pairing has not been authorized"}',
        :status => 601
      )
    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    assert_raise PairingDeactivatedError do
      auth_request = toopher.authenticate_by_user_name('user', 'terminal name')
    end
  end

  def test_one_user_to_enable_raises_no_error()
    stub_http_request(:get, "https://toopher.test/v1/users?name=user").
      to_return(
        :body => [ {
            "requester" => {
              "name" => "toopher.test",
              "id" => "requester1"
            },
            "id" => "user1",
            "name" => "user"
          } ].to_json,
        :status => 200
      )
    stub_http_request(:post, "https://toopher.test/v1/users/user1").
      to_return(
        :body => {
          "disable_toopher_auth" => true,
          "name" => "test",
          "requester" => {
            "name" => "toopher.com",
            "id" => "requester1"
          },
          "id" => "user1",
        }.to_json,
        :status => 200
      )
    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    auth_request = toopher.set_toopher_enabled_for_user('user', 'true')
  end

  def test_no_user_to_enable_raises_correct_error()
    stub_http_request(:get, "https://toopher.test/v1/users?name=user").
      to_return(
        :body => [ ].to_json,
        :status => 200
      )
    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    assert_raise ToopherApiError do
      auth_request = toopher.set_toopher_enabled_for_user('user', 'true')
    end
  end

  def test_multiple_users_to_enable_raises_correct_error()
    stub_http_request(:get, "https://toopher.test/v1/users?name=user").
      to_return(
        :body => [
          {
            "requester" => {
              "name" => "toopher.test",
              "id" => "requester1"
            },
            "id" => "user1",
            "name" => "user"
          },
          {
            "requester" => {
              "name" => "toopher.test",
              "id" => "requester1",
            },
            "id" => "user2",
            "name" => "user"
          }
        ].to_json,
        :status => 200
      )
    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    assert_raise ToopherApiError do
      auth_request = toopher.set_toopher_enabled_for_user('user', 'true')
    end
  end

  def test_version_string_exists()
    major, minor, patch = ToopherAPI::VERSION.split('.')
    assert(major >= '1', 'version string (major level) is invalid')
    assert(minor >= '0', 'version string (minor level) is invalid')
    assert(patch >= '0', 'version string (patch level) is invalid')
    assert(ToopherAPI::VERSION >= '1.0.6', 'version string does not exist')
  end

  def test_gemspec_version_matches_version_string()
    version_string = File.open('toopher_api.gemspec').grep(/version/).first
    gemspec_version = /version\s+=\s+'([\d.]+)'/.match(version_string).captures.first
    assert(ToopherAPI::VERSION == gemspec_version, "version strings do not match: library = #{ToopherAPI::VERSION} and gemspec = #{gemspec_version}")
  end
end

