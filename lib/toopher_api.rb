=begin
Copyright (c) 2012 Toopher, Inc

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
=end

require 'rubygems'
require 'net/http'
require 'net/https'
require 'uri'
require 'json'
require 'oauth'
require 'uuidtools'

# An exception class used to indicate an error returned by a Toopher API request
class ToopherApiError < StandardError
end

# Exceptions that can be used for control flow when using zero-storage
class UserDisabledError < ToopherApiError
end

class UnknownUserError < ToopherApiError
end

class UnknownTerminalError < ToopherApiError
end

class PairingDeactivatedError< ToopherApiError
end

# Abstracts calls to the Toopher OAuth webservice
class ToopherAPI
  # Version of the library
  VERSION = '1.1.0'

  # Default URL for the Toopher webservice API.  Can be overridden in the constructor if necessary.
  DEFAULT_BASE_URL = 'https://api.toopher.com/v1/'

  # @!attribute advanced
  #   @return [AdvancedApiUsageFactory] Holds advanced methods of Toopher API
  attr_accessor :advanced

  # Creates a Toopher API consumer
  #
  # @param [String] key Your Toopher API Key
  # @param [String] secret Your Toopher API Secret
  # @param [Hash] options OAuth Options hash.
  # @param [string] base_url The base URL to use for the Toopher API
  def initialize(key, secret, options = {}, base_url = DEFAULT_BASE_URL)
    @advanced = AdvancedApiUsageFactory.new(key, secret, options, base_url)
  end

  # Create the pairing between a particular user and their mobile device
  #
  # @param [String] username A human recognizable string which represents the user making the request (usually their username). This is displayed to the user on the mobile app when authenticating.
  # @param [String] phrase_or_num Either the pairing phrase generated by a user's mobile application or the user's phone number. If neither is provided, the pairing will be done by QR code.
  #
  # @return [Pairing] Information about the pairing request
  def pair(username, phrase_or_num = '', **kwargs)
    params = kwargs.merge(:user_name => username)

    if phrase_or_num.empty?
      url = 'pairings/create/qr'
    elsif phrase_or_num =~ /\d/
      url = 'pairings/create/sms'
      params[:phone_number] = phrase_or_num
    else
      url = 'pairings/create'
      params[:pairing_phrase] = phrase_or_num
    end

    return Pairing.new(@advanced.raw.post(url, params))
  end

  # Check on the status of a previous pairing request
  #
  # @param [String] pairing_id The unique string identifier id returned by a previous pairing request.
  #
  # @return [Pairing] Information about the pairing request
  def get_pairing_by_id(pairing_id)
    return Pairing.new(@advanced.raw.get('pairings/' + pairing_id))
  end

  # Authenticate an action with Toopher
  #
  # @param [String] id_or_username The unique string identifier id returned by a previous pairing request or the username of the pairing's user.
  # @param [String] terminal Either the terminal_name, a human recognizable string which represents the terminal from which the user is making the request, or terminal_name_extra, a string to help differentiate identically named terminals. The terminal_name would be displayed to the user on the mobile app when authenticating. If this is not included, then a terminal_id returned from a previous request must be provided (see below). These should be unique values for each different device from which a user connects to your service (as best you can detect).
  # @param [String] action_name Optional action name, defaults to "log in" (displayed to the user)
  #
  # @return [AuthenticationRequest] Information about the authentication request
  def authenticate(id_or_username, terminal = '', action_name = '', **kwargs)
    begin
      UUIDTools::UUID.parse(id_or_username)
      params = {
        :pairing_id => id_or_username,
        :terminal_name => terminal
      }
    rescue
      params = {
        :user_name => id_or_username,
        :terminal_name_extra => terminal
      }
    end

    params['action_name'] = action_name unless action_name.empty?
    params.merge!(kwargs)

    return AuthenticationRequest.new(@advanced.raw.post('authentication_requests/initiate', params))
  end

  # Check on the status of a previous authentication request
  #
  # @param [String] authentication_request_id The unique string identifier id returned by a previous authentication request.
  def get_authentication_request_by_id(authentication_request_id)
    return AuthenticationRequest.new(@advanced.raw.get('authentication_requests/' + authentication_request_id))
  end

  def create_user_terminal(username, terminal_name, requester_terminal_id, **kwargs)
    params = {
      :user_name => username,
      :name => terminal_name,
      :name_extra => requester_terminal_id
    }
    params.merge!(kwargs)
    return UserTerminal.new(@advanced.raw.post('user_terminals/create', params))
  end

  def get_user_terminal_by_id(terminal_id)
    return UserTerminal.new(@advanced.raw.get('user_terminals/' + terminal_id))
  end

  def create_user(username, **kwargs)
    params = { :name => username }
    params.merge!(kwargs)
    return User.new(@advanced.raw.post('users/create', params))
  end

  def get_user_by_id(user_id)
    return User.new(@advanced.raw.get('users/' + user_id))
  end

  def enable_user(username)
    set_toopher_disabled_for_user(username, false)
  end

  def disable_user(username)
    set_toopher_disabled_for_user(username, true)
  end

  def reset_user(username)
    params = { :name => username }
    @advanced.raw.post('users/reset', params)
    return true # would raise error in parse_request_error() if failed
  end

  private
  def set_toopher_disabled_for_user(username, disable)
    params = { :name => username }
    users = @advanced.raw.get('users', params)
    if users.count > 1
      raise ToopherApiError, 'Multiple users with name = #{username}'
    elsif users.count == 0
      raise ToopherApiError, 'No users with name = #{username}'
    end
    url = 'users/' + users[0]['id']
    params = { :disable_toopher_auth => disable }
    result = @advanced.raw.post(url, params)
  end
end

# Contains advanced API methods
class AdvancedApiUsageFactory
  # @!attribute raw
  #   @return [ApiRawRequester] Holds HTTP Request methods.
  attr_accessor :raw

  # Creates an AdvancedApiUsageFactory for Toopher API advanced methods
  #
  # @param [String] key Your Toopher API Key
  # @param [String] secret Your Toopher API Secret
  # @param [Hash] options OAuth Options hash.
  # @param [string] base_url The base URL to use for the Toopher API
  def initialize(key, secret, options, base_url)
    @raw = ApiRawRequester.new(key, secret, options, base_url)
  end
end

# Contains HTTP Request methods
class ApiRawRequester
  # Version of the library
  VERSION = '1.1.0'

  # Creates a ApiRawRequester for using HTTP request methods
  #
  # @param [String] key Your Toopher API Key
  # @param [String] secret Your Toopher API Secret
  # @param [Hash] options OAuth Options hash.
  # @param [string] base_url The base URL to use for the Toopher API
  def initialize(key, secret, options, base_url)
    consumer_key = key
    consumer_secret = secret

    consumer_key.empty? and raise ArgumentError, "Toopher consumer key cannot be empty!"
    consumer_secret.empty? and raise ArgumentError, "Toopher consumer secret cannot be empty!"

    @oauth_consumer = OAuth::Consumer.new(consumer_key, consumer_secret)
    @oauth_options = options
    @base_url = base_url
  end

  def post(endpoint, **kwargs)
    url = URI.parse(@base_url + endpoint)
    req = Net::HTTP::Post.new(url.path)
    req.set_form_data(kwargs)
    return request(url, req)
  end

  def get(endpoint, **kwargs)
    url = URI.parse(@base_url + endpoint)
    if kwargs.empty?
      req = Net::HTTP::Get.new(url.path)
    else
      req = Net::HTTP::Get.new(url.path + '?' + URI.encode_www_form(kwargs))
    end
    return request(url, req)
  end

  private
  def request(url, req)
    req['User-Agent'] = "Toopher-Ruby/#{VERSION} (Ruby #{RUBY_VERSION})"
    http = Net::HTTP::new(url.host, url.port)
    http.use_ssl = url.port == 443
    req.oauth!(http, @oauth_consumer, nil, @oauth_options)
    res = http.request(req)
    decoded = JSON.parse(res.body)
    parse_request_error(decoded) if res.code.to_i >= 400
    return decoded
  end

  def parse_request_error(decoded)
    if(decoded.has_key?("error_code"))
      error_code, error_message = decoded['error_code'], decoded['error_message']
      if error_code == 704
        raise UserDisabledError, "Error code #{error_code.to_s} : #{error_message}"
      elsif error_code == 705
        raise UnknownUserError, "Error code #{error_code.to_s} : #{error_message}"
      elsif error_code == 706
        raise UnknownTerminalError, "Error code #{error_code.to_s} : #{error_message}"
      elsif error_message =~ /pairing has not been authorized|pairing has been deactivated/i
        raise PairingDeactivatedError, "Error code #{error_code.to_s} : #{error_message}"
      else
        raise ToopherApiError,"Error code #{error_code.to_s} : #{error_message}"
      end
    end
  end
end

# Contains information about a particular pairing request
class Pairing

  # @!attribute id
  #   @return [String] A unique identifier generated and returned by the Toopher web service that is used to identify this pairing. It can be used to request status information for the pairing and must be included in subsequent authentication requests for this user.
  attr_accessor :id

  # @!attribute enabled
  #   @return [Boolean] Indicates whether or not the pairing has been acknowledged and enabled by the user.
  attr_accessor :enabled

  # @!attribute pending
  #   @return [Boolean] Indicates whether or not the pairing is waiting to be acknowledged and enabled or denied by the user.
  attr_accessor :pending

  # @!attribute user
  #   @return [User] Contains information about the User associated with this Pairing
  attr_accessor :user

  # @!attribute raw
  #   @return [hash] The raw data returned from the Toopher API
  attr_accessor :raw

  def initialize(json_obj)
    @user = User.new(json_obj['user'])
    update(json_obj)
  end

  def refresh_from_server(api)
    result = api.advanced.raw.get('pairings/' + @id)
    update(result)
  end

  def get_reset_link(api, **kwargs)
    url = 'pairings/' + @id + '/generate_reset_link'
    result = api.advanced.raw.post(url, kwargs)
    return result['url']
  end

  def email_reset_link_to_user(api, email, **kwargs)
    url = 'pairings/' + @id + '/send_reset_link'
    params = { :reset_email => email }
    params.merge!(kwargs)
    api.advanced.raw.post(url, params)
    return true # would raise error in parse_request_error() if failed
  end

  def update(json_obj)
    @id = json_obj['id']
    @enabled = json_obj['enabled']
    @pending = json_obj['pending']
    @user.update(json_obj['user'])
    @raw = json_obj
  end
end

# Contains information about a particular authentication request
class AuthenticationRequest

  # @!attribute id
  #   @return [String] A unique string identifier generated and returned by the Toopher web service that is used to identify this authentication request. It can be used to request status information for the authentication request.
  attr_accessor :id

  # @!attribute pending
  #   @return [Boolean] Indicates whether the request is still pending.
  attr_accessor :pending

  # @!attribute granted
  #   @return [Boolean] Indicates whether the request was granted.
  attr_accessor :granted

  # @!attribute automated
  #   @return [Boolean] Indicates whether the request was automated.
  attr_accessor :automated

  # @!attribute reason
  #   @return  [String]A string which provides additional information about the reason for the authentication outcome (if available).
  attr_accessor :reason

  # @!attribute terminal
  #   @return  [Terminal] Contains information about the Terminal associated with this AuthenticationRequest
  attr_accessor :terminal

  # @!attribute raw
  #   @return [hash] The raw data returned from the Toopher API
  attr_accessor :raw

  def initialize(json_obj)
    @terminal = UserTerminal.new(json_obj['terminal'])
    update(json_obj)
  end

  def refresh_from_server(api)
    result = api.advanced.raw.get('authentication_requests/' + @id)
    update(result)
  end

  def authenticate_with_otp(otp, api, **kwargs)
    url = 'authentication_requests/' + @id + '/otp_auth'
    params = { :otp => otp }
    params.merge!(kwargs)
    result = api.advanced.raw.post(url, params)
    return AuthenticationRequest.new(result)
  end

  def update(json_obj)
    @id = json_obj['id']
    @pending = json_obj['pending']
    @granted = json_obj['granted']
    @automated = json_obj['automated']
    @reason = json_obj['reason']
    @terminal.update(json_obj['terminal'])
    @raw = json_obj
  end
end

class UserTerminal
  # @!attribute id
  #   @return [String] A unique string identifier generated and returned by the Toopher web service that is used to identify this user terminal. It can be used to request status information for the user terminal.
  attr_accessor :id

  # @!attribute name
  #   @return [String] The human recognizable terminal name associated with the given id.
  attr_accessor :name

  # @!attribute name_extra
  #   @return [String] A string to help differentiate identically named terminals.
  attr_accessor :name_extra

  # @!attribute user_id
  #   @return [String] A unique identifier generated and returned by the Toopher web service for a given user.
  attr_accessor :user_id

  # @!attribute user_name
  #   @return [String] The human recognizable user name associated with the given id.
  attr_accessor :user_name

  # @!attribute raw
  #   @return [hash] The raw data returned from the Toopher API
  attr_accessor :raw

  def initialize(json_obj)
    update(json_obj)
  end

  def refresh_from_server(api)
    result = api.advanced.raw.get('user_terminals/' + @id)
    update(result)
  end

  def update(json_obj)
    @id = json_obj['id']
    @name = json_obj['name']
    @name_extra = json_obj['name_extra']
    @user_id = json_obj['user']['id']
    @user_name = json_obj['user']['name']
    @raw = json_obj
  end
end

class User
  # @!attribute id
  #   @return [String] A unique string identifier generated and returned by the Toopher web service that is used to identify this user terminal. It can be used to request status information for the user terminal.
  attr_accessor :id

  # @!attribute name
  #   @return [String] The human recognizable user name associated with the given id.
  attr_accessor :name

  # @!attribute disable_toopher_auth
  #   @return [Boolean] Whether or not this user has Toopher authentication enabled or disabled.
  attr_accessor :disable_toopher_auth

  # @!attribute raw
  #   @return [hash] The raw data returned from the Toopher API
  attr_accessor :raw

  def initialize(json_obj)
    update(json_obj)
  end

  def refresh_from_server(api)
    result = api.advanced.raw.get('users/' + @id)
    update(result)
  end

  def enable(api)
    params = { :disable_toopher_auth => false }
    api.advanced.raw.post('users/' + @id, params)
    @disable_toopher_auth = false
    @raw['disable_toopher_auth'] = false
  end

  def disable(api)
    params = { :disable_toopher_auth => true }
    api.advanced.raw.post('users/' + @id, params)
    @disable_toopher_auth = true
    @raw['disable_toopher_auth'] = true
  end

  def reset(api)
    return api.reset_user(@name)
  end

  def update(json_obj)
    @id = json_obj['id']
    @name = json_obj['name']
    @disable_toopher_auth = json_obj['disable_toopher_auth']
    @raw = json_obj
  end
end