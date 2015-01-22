require 'rubygems'
require 'test/unit'
require 'webmock/test_unit'
require 'toopher_api'
require 'uuidtools'

class TestToopher < Test::Unit::TestCase
  def setup
    @toopher = ToopherAPI.new('key', 'secret', { :nonce => 'nonce', :timestamp => '0' }, base_url = 'https://toopher.test/v1/')
    @user = {
      :id => UUIDTools::UUID.random_create().to_str(),
      :name => 'user',
      :disable_toopher_auth => false
    }
    @pairing = {
      :id => UUIDTools::UUID.random_create().to_str(),
      :enabled => true,
      :pending => false,
      :user => @user
    }
    @terminal = {
      :id => UUIDTools::UUID.random_create().to_str(),
      :name => 'term name',
      :name_extra => 'requester terminal id',
      :user => @user
    }
    @auth_request = {
      :id => UUIDTools::UUID.random_create().to_str(),
      :pending => false,
      :granted => true,
      :automated => true,
      :reason => 'some reason',
      :terminal => @terminal,
      :user => @user
    }
  end

  def compare_to_default_terminal(actual_terminal)
    assert(actual_terminal.id == @terminal[:id], 'wrong terminal id')
    assert(actual_terminal.name == @terminal[:name], 'wrong terminal name')
    assert(actual_terminal.name_extra == @terminal[:name_extra], 'wrong terminal name extra')
    assert(actual_terminal.user.name == @terminal[:user][:name], 'wrong user name')
    assert(actual_terminal.user.id == @terminal[:user][:id], 'wrong user id')
    assert(actual_terminal.raw['user']['name'] == @terminal[:user][:name], 'could not access raw data')
  end

  def compare_to_default_pairing(actual_pairing)
    assert(actual_pairing.id == @pairing[:id], 'bad pairing id')
    assert(actual_pairing.enabled == @pairing[:enabled], 'bad pairing enabled')
    assert(actual_pairing.pending == @pairing[:pending], 'bad pairing pending')
    assert(actual_pairing.user.id == @pairing[:user][:id], 'bad user id')
    assert(actual_pairing.user.name == @pairing[:user][:name], 'bad user name')
    assert(actual_pairing.raw['user']['name'] == @pairing[:user][:name], 'could not access raw data')
  end

  def compare_to_default_auth_request(actual_auth_request)
    assert(actual_auth_request.id == @auth_request[:id], 'bad auth id')
    assert(actual_auth_request.pending == @auth_request[:pending], 'bad auth pending')
    assert(actual_auth_request.granted == @auth_request[:granted], 'bad auth granted')
    assert(actual_auth_request.automated == @auth_request[:automated], 'bad auth automated')
    assert(actual_auth_request.reason == @auth_request[:reason], 'bad auth reason')
    assert(actual_auth_request.terminal.id == @auth_request[:terminal][:id], 'bad auth terminal id')
    assert(actual_auth_request.terminal.name == @auth_request[:terminal][:name], 'bad auth terminal name')
    assert(actual_auth_request.terminal.name_extra == @auth_request[:terminal][:name_extra], 'bad auth terminal name')
    assert(actual_auth_request.raw['terminal']['name_extra'] == @auth_request[:terminal][:name_extra], 'bad auth terminal name')
  end

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
        :body => {
          :pairing_phrase => 'immediate_pair',
          :user_name => @user[:name]
        }
      ).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

      pairing = @toopher.pair(@user[:name], 'immediate_pair')
      compare_to_default_pairing(pairing)
  end

  def test_create_pairing_with_optional_arg()
    stub_http_request(:post, "https://toopher.test/v1/pairings/create").
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

      pairing = @toopher.pair(@user[:name], 'immediate_pair', :test_param => 'foo')
      compare_to_default_pairing(pairing)
  end

  def test_create_sms_pairing_success()
    stub_http_request(:post, "https://toopher.test/v1/pairings/create/sms").
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

    pairing = @toopher.pair(@user[:name], '555-555-5555')
    compare_to_default_pairing(pairing)

    stub_http_request(:post, "https://toopher.test/v1/pairings/create/sms").
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

    pairing = @toopher.pair(@user[:name], '555-555-5555', :country_code => '1')
    compare_to_default_pairing(pairing)
  end

  def test_create_qr_pairing_success()
    stub_http_request(:post, "https://toopher.test/v1/pairings/create/qr").
      with(
        :body => {
          :user_name => @user[:name]
        }
      ).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

    pairing = @toopher.pair(@user[:name])
    compare_to_default_pairing(pairing)
  end

  def test_get_pairing_by_id()
    stub_http_request(:get, "https://toopher.test/v1/pairings/1").
      to_return(
        :body => {
          :id => '1',
          :enabled => true,
          :pending => false,
          :user => {
            :id => '1',
            :name => 'paired user',
            :disable_toopher_auth => false
          }
        }.to_json,
        :status => 200
      )
    stub_http_request(:get, "https://toopher.test/v1/pairings/2").
      to_return(
        :body => {
          :id => '2',
          :enabled => false,
          :pending => true,
          :user => {
            :id => '2',
            :name => 'unpaired user',
            :disable_toopher_auth => false
          }
        }.to_json,
        :status => 200
      )

      pairing = @toopher.advanced.pairings.get_by_id('1')
      assert(pairing.id == '1', 'bad pairing id')
      assert(pairing.enabled == true, 'pairing not enabled')
      assert(pairing.pending == false, 'pairing is pending')
      assert(pairing.user.id == '1', 'bad user id')
      assert(pairing.user.name == 'paired user', 'bad user name')

      pairing = @toopher.advanced.pairings.get_by_id('2')
      assert(pairing.id == '2', 'bad pairing id')
      assert(pairing.enabled == false, 'pairing should not be enabled')
      assert(pairing.pending == true, 'pairing is not pending')
      assert(pairing.user.id == '2', 'bad user id')
      assert(pairing.user.name == 'unpaired user', 'bad user name')
  end

  def test_create_authentication_with_no_action()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
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

    auth_request = @toopher.authenticate(@pairing[:id], @terminal[:name])
    compare_to_default_auth_request(auth_request)
  end

  def test_create_authentication_with_optional_arg()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
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

    auth_request = @toopher.authenticate(@auth_request[:id], @terminal[:name], :test_param => 'foo')
    compare_to_default_auth_request(auth_request)
  end

  def test_create_authentication_with_username()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      with(
        :body => {
          :user_name => @user[:name],
          :terminal_name_extra => @terminal[:name_extra]
        }
      ).
      to_return(
        :body => @auth_request.to_json,
        :status => 200
      )

    auth_request = @toopher.authenticate(@user[:name], @terminal[:name_extra])
    compare_to_default_auth_request(auth_request)
  end

  def test_get_authentication_request_by_id()
    stub_http_request(:get, "https://toopher.test/v1/authentication_requests/" + @auth_request[:id]).
      to_return(
        :body => @auth_request.to_json,
        :status => 200
      )

    auth_request = @toopher.advanced.authentication_requests.get_by_id(@auth_request[:id])
    compare_to_default_auth_request(auth_request)
  end

  def test_create_user_terminal()
    stub_http_request(:post, 'https://toopher.test/v1/user_terminals/create').
      with(
        :body => {
          :user_name => @user[:name],
          :name => @terminal[:name],
          :name_extra => @terminal[:name_extra]
        }
      ).
      to_return(
        :body => @terminal.to_json,
        :status => 200
      )

    terminal = @toopher.create_user_terminal(@user[:name], @terminal[:name], @terminal[:name_extra])
    compare_to_default_terminal(terminal)
  end

  def test_get_user_terminal_by_id()
    stub_http_request(:get, 'https://toopher.test/v1/user_terminals/' + @terminal[:id]).
      to_return(
        :body => @terminal.to_json,
        :status => 200
      )

    terminal = @toopher.get_user_terminal_by_id(@terminal[:id])
    compare_to_default_terminal(terminal)
  end

  def test_create_user()
    stub_http_request(:post, 'https://toopher.test/v1/users/create').
      with(
        :body => {
          :name => @user[:name]
        }
      ).
      to_return(
        :body => @user.to_json,
        :status => 200
      )

    user = @toopher.create_user(@user[:name])
    assert(user.id == @user[:id], 'wrong user id')
    assert(user.name == @user[:name], 'wrong user name')
    assert(user.disable_toopher_auth == @user[:disable_toopher_auth], 'wrong user disabled status')
  end

  def test_get_user_by_id()
    stub_http_request(:get, 'https://toopher.test/v1/users/' + @user[:id]).
      to_return(
        :body => @user.to_json,
        :status => 200
      )

    user = @toopher.get_user_by_id(@user[:id])
    assert(user.id == @user[:id], 'wrong user id')
    assert(user.name == @user[:name], 'wrong user name')
    assert(user.disable_toopher_auth == @user[:disable_toopher_auth], 'wrong user disabled status')
  end

  def disable_user(disable)
    user = User.new(
      'id' => '1',
      'name' => 'user name',
      'disable_toopher_auth' => !disable
    )

    stub_http_request(:get, 'https://toopher.test/v1/users?name=' + user.name).
      to_return(
        :body => [
          {
            :id => user.id,
            :name => user.name,
            :disable_toopher_auth => !disable
          }
        ].to_json,
        :status => 200
      )

    stub_http_request(:post, 'https://toopher.test/v1/users/1').
      with(
        :body => {
          :disable_toopher_auth => disable.to_s
        }
      ).
      to_return(
        :body => '{}',
        :status => 200
      )

    assert_nothing_raised do
      if disable
        @toopher.disable_user(user.name)
      else
        @toopher.enable_user(user.name)
      end
    end

    stub_http_request(:get, 'https://toopher.test/v1/users/1').
      to_return(
        :body => {
            :id => '1',
            :name => 'user name',
            :disable_toopher_auth => disable
        }.to_json,
        :status => 200
      )
    user = @toopher.get_user_by_id(user.id)
    assert(user.id == '1', 'wrong user id')
    assert(user.name == 'user name', 'wrong user name')
    assert(user.disable_toopher_auth == disable, 'user should be enabled')
  end

  def test_enable_user()
    disable_user(false)
  end

  def test_disable_user()
    disable_user(true)
  end

  def test_no_user_to_enable_raises_correct_error()
    stub_http_request(:get, "https://toopher.test/v1/users?name=user").
      to_return(
        :body => '[]',
        :status => 200
      )
    assert_raise ToopherApiError do
      auth_request = @toopher.enable_user('user')
    end
  end

  def test_multiple_users_to_enable_raises_correct_error()
    stub_http_request(:get, "https://toopher.test/v1/users?name=user").
      to_return(
        :body => [
          {
            :requester => {
              :name => 'toopher.test',
              :id => 'requester1'
            },
            :id => 'ser1',
            :name => 'user'
          },
          {
            :requester => {
              :name => 'toopher.test',
              :id => 'requester1',
            },
            :id => 'user2',
            :name => 'user'
          }
        ].to_json,
        :status => 200
      )
    assert_raise ToopherApiError do
      auth_request = @toopher.enable_user('user')
    end
  end

  def test_get()
    stub_http_request(:get, 'https://toopher.test/v1/pairings/' + @pairing[:id]).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

    result = @toopher.advanced.raw.get('pairings/' + @pairing[:id])
    assert(result['id'] == @pairing[:id], 'wrong pairing id')
    assert(result['enabled'] == @pairing[:enabled], 'pairing should be enabled')
    assert(result['pending'] == @pairing[:pending], 'pairing should not be pending')
    assert(result['user']['id'] == @pairing[:user][:id], 'wrong user id')
    assert(result['user']['name'] == @pairing[:user][:name], 'wrong user name')
  end

  def test_post()
    stub_http_request(:post, 'https://toopher.test/v1/user_terminals/create').
      with(
        :body => {
          :name => @terminal[:name],
          :name_extra => @terminal[:name_extra],
          :user_name => @terminal[:user][:name]
        }
      ).
      to_return(
        :body => @terminal.to_json,
        :status => 200
      )

    result = @toopher.advanced.raw.post('user_terminals/create', :name => @terminal[:name], :name_extra => @terminal[:name_extra], :user_name => @terminal[:user][:name])
    assert(result['id'] == @terminal[:id], 'wrong terminal id')
    assert(result['name'] == @terminal[:name], 'wrong terminal name')
    assert(result['name_extra'] == @terminal[:name_extra], 'wrong terminal name extra')
    assert(result['user']['id'] == @terminal[:user][:id], 'wrong user id')
    assert(result['user']['name'] == @terminal[:user][:name], 'wrong user name')
  end

  def test_toopher_request_error()
    stub_http_request(:get, "https://toopher.test/v1/authentication_requests/1").
      to_return(
        :body => {
          :error_code => 401,
          :error_message => 'Not a valid OAuth signed request'
        }.to_json,
        :status => 401
      )
    assert_raise ToopherApiError do
      auth = @toopher.advanced.authentication_requests.get_by_id('1')
    end
  end

  def test_disabled_user_raises_correct_error()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => {
          :error_code => 704,
          :error_message => 'disabled user'
        }.to_json,
        :status => 409
      )
    assert_raise UserDisabledError do
      auth_request = @toopher.authenticate('disabled user', 'terminal name')
    end
  end

  def test_unknown_user_raises_correct_error()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => {
          :error_code => 705,
          :error_message => 'disabled user'
        }.to_json,
        :status => 409
      )
    assert_raise UnknownUserError do
      auth_request = @toopher.authenticate('unknown user', 'terminal name')
    end
  end

  def test_unknown_terminal_raises_correct_error()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => {
          :error_code => 706,
          :error_message => 'unknown terminal'
        }.to_json,
        :status => 409
      )
    assert_raise UnknownTerminalError do
      auth_request = @toopher.authenticate('user', 'unknown terminal name')
    end
  end

  def test_disabled_pairing_raises_correct_error()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => {
          :error_code => 601,
          :error_message => 'pairing has been deactivated'
        }.to_json,
        :status => 601
      )
    assert_raise PairingDeactivatedError do
      auth_request = @toopher.authenticate('user', 'terminal name')
    end
  end

  def test_unauthorized_pairing_raises_correct_error()
    stub_http_request(:post, "https://toopher.test/v1/authentication_requests/initiate").
      to_return(
        :body => {
          :error_code => 601,
          :error_message => 'pairing has not been authorized'
        }.to_json,
        :status => 601
      )
    assert_raise PairingDeactivatedError do
      auth_request = @toopher.authenticate('user', 'terminal name')
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

class TestPairing < Test::Unit::TestCase
  def setup
    @toopher = ToopherAPI.new('key', 'secret', { :nonce => 'nonce', :timestamp => '0' }, base_url = 'https://toopher.test/v1/')
    @user = {
      'id' => UUIDTools::UUID.random_create().to_str(),
      'name' => 'user',
      'disable_toopher_auth' => false
    }
    @pairing = {
      'id' => UUIDTools::UUID.random_create().to_str(),
      'enabled' => true,
      'pending' => false,
      'user' => @user
    }
  end

  def test_constructor()
    assert_nothing_raised do
      pairing = Pairing.new(@pairing)

      assert(pairing.id == @pairing['id'], 'bad pairing id')
      assert(pairing.enabled == @pairing['enabled'], 'pairing should not be enabled')
      assert(pairing.pending == @pairing['pending'], 'pairing should be pending')
      assert(pairing.user.id == @pairing['user']['id'], 'bad user id')
      assert(pairing.user.name == @pairing['user']['name'], 'bad user name')
    end
  end

  def test_refresh_from_server()
    pairing1 = Pairing.new(
      'id' => '1',
      'enabled' => false,
      'pending' => true,
      'user' => {
        'id' => '1',
        'name' => 'user 1',
        'disable_toopher_auth' => false
      }
    )
    pairing2 = Pairing.new(
      'id' => '2',
      'enabled' => false,
      'pending' => true,
      'user' => {
        'id' => '2',
        'name' => 'user 2',
        'disable_toopher_auth' => false
      }
    )

    stub_http_request(:get, "https://toopher.test/v1/pairings/1").
      to_return(
        :body => {
          :id => '1',
          :enabled => true,
          :pending => false,
          :user => {
            :id => '1',
            :name => 'paired user changed name',
            :disable_toopher_auth => false
          }
        }.to_json,
        :status => 200
      )
    stub_http_request(:get, "https://toopher.test/v1/pairings/2").
      to_return(
        :body => {
          :id => '2',
          :enabled => false,
          :pending => false,
          :user => {
            :id => '2',
            :name => 'unpaired user changed name',
            :disable_toopher_auth => false
          }
        }.to_json,
        :status => 200
      )

    pairing1.refresh_from_server(@toopher)
    assert(pairing1.id == '1', 'bad pairing id')
    assert(pairing1.enabled == true, 'pairing not enabled')
    assert(pairing1.pending == false, 'pairing is pending')
    assert(pairing1.user.id == '1', 'bad user id')
    assert(pairing1.user.name == 'paired user changed name', 'bad user name')

    pairing2.refresh_from_server(@toopher)
    assert(pairing2.id == '2', 'bad pairing id')
    assert(pairing2.enabled == false, 'pairing should not be enabled')
    assert(pairing2.pending == false, 'pairing is pending')
    assert(pairing2.user.id == '2', 'bad user id')
    assert(pairing2.user.name == 'unpaired user changed name', 'bad user name')
  end

  def test_get_reset_link()
    stub_http_request(:get, 'https://toopher.test/v1/pairings/' + @pairing['id']).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

    stub_http_request(:post,'https://toopher.test/v1/pairings/' + @pairing['id'] + '/generate_reset_link').
      to_return(
        :body => {
          :url => 'http://toopher.test/v1/pairings/' + @pairing['id'] + '/reset?reset_authorization=abcde'
        }.to_json,
        :status => 200
      )
    pairing = @toopher.advanced.pairings.get_by_id(@pairing['id'])
    reset_link = pairing.get_reset_link(@toopher)
    assert(reset_link == 'http://toopher.test/v1/pairings/' + @pairing['id'] + '/reset?reset_authorization=abcde')
  end

  def test_email_reset_link_to_user()
    stub_http_request(:get, 'https://toopher.test/v1/pairings/' + @pairing['id']).
      to_return(
        :body => @pairing.to_json,
        :status => 200
      )

    stub_http_request(:post, 'https://toopher.test/v1/pairings/' + @pairing['id'] + '/send_reset_link').
      with(
        :body => {
          :reset_email => 'email'
        }
      ).
      to_return(
        :body => '[]',
        :status => 201
      )
    pairing = @toopher.advanced.pairings.get_by_id(@pairing['id'])
    assert_nothing_raised do
      pairing.email_reset_link_to_user(@toopher, 'email')
    end
  end
end

class TestAuthenticationRequest < Test::Unit::TestCase
  def setup
    @toopher = ToopherAPI.new('key', 'secret', { :nonce => 'nonce', :timestamp => '0' }, base_url = 'https://toopher.test/v1/')
    @user = {
      'id' => UUIDTools::UUID.random_create().to_str(),
      'name' => 'user',
      'disable_toopher_auth' => false
    }
    @terminal = {
      'id' => UUIDTools::UUID.random_create().to_str(),
      'name' => 'term name',
      'name_extra' => 'requester terminal id',
      'user' => @user
    }
    @auth_request = {
      'id' => UUIDTools::UUID.random_create().to_str(),
      'pending' => false,
      'granted' => true,
      'automated' => true,
      'reason' => 'some reason',
      'terminal' => @terminal,
      'user' => @user
    }
  end

  def test_constructor()
    assert_nothing_raised do
      auth_request = AuthenticationRequest.new(@auth_request)

      assert(auth_request.id == @auth_request['id'], 'bad auth request id')
      assert(auth_request.pending == @auth_request['pending'], 'bad auth_request pending status')
      assert(auth_request.granted == @auth_request['granted'], 'bad auth_request granted status')
      assert(auth_request.automated == @auth_request['automated'], 'bad auth_request automated status')
      assert(auth_request.reason == @auth_request['reason'], 'bad auth_request reason')
      assert(auth_request.terminal.id == @auth_request['terminal']['id'], 'bad terminal id')
      assert(auth_request.terminal.name == @auth_request['terminal']['name'], 'bad terminal name')
      assert(auth_request.terminal.name_extra == @auth_request['terminal']['name_extra'], 'bad terminal name extra')
      assert(auth_request.user.id == @auth_request['user']['id'], 'bad user id')
      assert(auth_request.user.name == @auth_request['user']['name'], 'bad user name')
      assert(auth_request.user.disable_toopher_auth == @auth_request['user']['disable_toopher_auth'], 'bad user disabled status')
    end
  end

  def test_refresh_from_server()
    auth_request = AuthenticationRequest.new(@auth_request)

    stub_http_request(:get, 'https://toopher.test/v1/authentication_requests/' + @auth_request['id']).
      to_return(
        :body => {
          :id => @auth_request['id'],
          :pending => false,
          :granted => true,
          :automated => true,
          :reason => 'reason has changed',
          :terminal => {
            :id => @auth_request['terminal']['id'],
            :name => 'term name changed',
            :name_extra => @auth_request['terminal']['name_extra'],
            :user => @auth_request['terminal']['user']
          },
          :user => @auth_request['terminal']['user']
        }.to_json,
        :status => 200
      )
    puts
    auth_request.refresh_from_server(@toopher)
    assert(auth_request.id == @auth_request['id'], 'bad auth request id')
    assert(auth_request.pending == false, 'auth request should not be pending')
    assert(auth_request.granted == true, 'auth request should be granted')
    assert(auth_request.automated == true, 'auth request should be automated')
    assert(auth_request.reason == 'reason has changed', 'bad auth request reason')
    assert(auth_request.terminal.id == @auth_request['terminal']['id'], 'bad terminal id')
    assert(auth_request.terminal.name == 'term name changed', 'bad terminal name')
    assert(auth_request.terminal.name_extra == @auth_request['terminal']['name_extra'], 'bad terminal name extra')
  end

  def test_authenticate_with_otp()
    auth_request = AuthenticationRequest.new(@auth_request)

    stub_http_request(:post, 'https://toopher.test/v1/authentication_requests/' + @auth_request['id'] + '/otp_auth').
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
          :terminal => {
            :id => @auth_request['terminal']['id'],
            :name => 'term name',
            :name_extra => 'requester terminal id',
            :user => @auth_request['terminal']['user']
          },
          :user => @auth_request['terminal']['user']
        }.to_json,
        :status => 200
      )

    auth_request_updated = auth_request.authenticate_with_otp('otp', @toopher)
    assert(auth_request_updated.id == @auth_request['id'], 'bad auth request id')
    assert(auth_request_updated.pending == false, 'auth request should not be pending')
    assert(auth_request_updated.granted == true, 'auth request should be granted')
    assert(auth_request_updated.automated == true, 'auth request should be automated')
    assert(auth_request_updated.reason == 'it is a test', 'bad auth request reason')
    assert(auth_request_updated.terminal.id == @auth_request['terminal']['id'], 'bad terminal id')
    assert(auth_request_updated.terminal.name == 'term name', 'bad terminal name')
    assert(auth_request_updated.terminal.name_extra == 'requester terminal id', 'bad terminal name extra')
  end
end

class TestUserTerminal < Test::Unit::TestCase
  def setup
    @toopher = ToopherAPI.new('key', 'secret', { :nonce => 'nonce', :timestamp => '0' }, base_url = 'https://toopher.test/v1/')
    @user = {
      'id' => UUIDTools::UUID.random_create().to_str(),
      'name' => 'user',
      'disable_toopher_auth' => false
    }
    @terminal = {
      'id' => UUIDTools::UUID.random_create().to_str(),
      'name' => 'term name',
      'name_extra' => 'requester terminal id',
      'user' => @user
    }
  end

  def test_constructor()
    assert_nothing_raised do
      terminal = UserTerminal.new(@terminal)

      assert(terminal.id == @terminal['id'], 'bad terminal id')
      assert(terminal.name == @terminal['name'], 'bad terminal name')
      assert(terminal.name_extra == @terminal['name_extra'], 'bad terminal name extra')
      assert(terminal.user.id == @terminal['user']['id'], 'bad user id')
      assert(terminal.user.name == @terminal['user']['name'], 'bad user name')
    end
  end

  def test_refresh_from_server()
    terminal = UserTerminal.new(@terminal)

    stub_http_request(:get, 'https://toopher.test/v1/user_terminals/' + @terminal['id']).
      to_return(
        :body => {
          :id => @terminal['id'],
          :name => 'term name changed',
          :name_extra => 'requester terminal id',
          :user => {
            :id => @terminal['user']['id'],
            :name => 'user name changed',
            :disable_toopher_auth => false
          }
        }.to_json,
        :status => 200
      )

    terminal.refresh_from_server(@toopher)
    assert(terminal.id == @terminal['id'], 'bad terminal id')
    assert(terminal.name == 'term name changed', 'bad terminal name')
    assert(terminal.name_extra == 'requester terminal id', 'bad terminal name extra')
    assert(terminal.user.id == @terminal['user']['id'], 'bad user id')
    assert(terminal.user.name == 'user name changed', 'bad user name')
  end
end

class TestUser < Test::Unit::TestCase
  def test_constructor()
    assert_nothing_raised do
      user = User.new(
        'id' => '1',
        'name' => 'user name',
        'disable_toopher_auth' => false
      )

      assert(user.id == '1', 'bad user id')
      assert(user.name == 'user name', 'bad user name')
      assert(user.disable_toopher_auth == false, 'user should be enabled')
    end
  end

  def test_refresh_from_server()
    user = User.new(
      'id' => '1',
      'name' => 'user name',
      'disable_toopher_auth' => false
    )

    stub_http_request(:get, 'https://toopher.test/v1/users/1').
      to_return(
        :body => {
          :id => '1',
          :name => 'user name changed',
          :disable_toopher_auth => true
        }.to_json,
        :status => 200
      )

    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    user.refresh_from_server(toopher)
    assert(user.id == '1', 'bad user id')
    assert(user.name == 'user name changed', 'bad user name')
    assert(user.disable_toopher_auth == true, 'user should be disabled')
  end

  def disable_user(disable)
    user = User.new(
      'id' => '1',
      'name' => 'user name',
      'disable_toopher_auth' => !disable
    )

    stub_http_request(:post, 'https://toopher.test/v1/users/1').
      with(
        :body => { 'disable_toopher_auth' => "#{disable}" }
      ).
      to_return(
        :body => '{}',
        :status => 200
      )

    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    assert_nothing_raised do
      if disable
        user.disable(toopher)
        assert(user.disable_toopher_auth == true, 'user should be disabled')
      else
        user.enable(toopher)
        assert(user.disable_toopher_auth == false, 'user should be enabled')
      end
    end
  end

  def test_enable()
    disable_user(false)
  end

  def test_disable()
    disable_user(true)
  end

  def test_reset_user()
    user = User.new(
      'id' => '1',
      'name' => 'user name',
      'disable_toopher_auth' => false
    )
    stub_http_request(:post, 'https://toopher.test/v1/users/reset').
      with(
        :body => { 'name' => 'user name'}
      ).
      to_return(
        :body => '[]',
        :status => 200
      )

    toopher = ToopherAPI.new('key', 'secret', {:nonce => 'nonce', :timestamp => '0' }, base_url="https://toopher.test/v1/")
    result = user.reset(toopher)
    assert(result == true)
  end
end