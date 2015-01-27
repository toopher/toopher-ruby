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
require 'time'
require 'openssl'
require 'base64'

# Default URL for the Toopher webservice API.  Can be overridden in the constructor if necessary.
DEFAULT_BASE_URL = 'https://api.toopher.com/v1/'

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

class SignatureValidationError< ToopherApiError
end

class ToopherIframe
  DEFAULT_IFRAME_TTL = 100
  IFRAME_VERSION = '2'

  def initialize(key, secret, options, base_url = DEFAULT_BASE_URL)
    key.empty? and raise ArgumentError, "Toopher consumer key cannot be empty!"
    secret.empty? and raise ArgumentError, "Toopher consumer secret cannot be empty!"

    @oauth_options = options.merge(:site => base_url, :scheme => :query_string)
    @oauth_consumer = OAuth::Consumer.new(key, secret, @oauth_options)
    @base_url = base_url
  end

  def get_user_management_url(username, reset_email, **kwargs)
    ttl = kwargs.delete(:ttl) || DEFAULT_IFRAME_TTL
    params = {
      :username => username,
      :reset_email => reset_email,
      :v => IFRAME_VERSION,
    }
    params.merge!(kwargs)
    return get_oauth_signed_url('web/manage_user', ttl, params)
  end

  def get_authentication_url(username, reset_email, request_token, action_name='Log In', requester_metadata='None', **kwargs)
    kwargs[:allow_inline_pairing] = true if kwargs[:allow_inline_pairing].nil?
    kwargs[:automation_allowed] = true if kwargs[:automation_allowed].nil?
    kwargs[:challenge_required] ||= false
    ttl = kwargs.delete(:ttl) || DEFAULT_IFRAME_TTL

    params = {
      :v => IFRAME_VERSION,
      :username => username,
      :reset_email => reset_email,
      :action_name => action_name,
      :session_token => request_token,
      :requester_metadata => requester_metadata,
    }
    params.merge!(kwargs)
    return get_oauth_signed_url('web/authenticate', ttl, params)
  end

  def validate_postback(data, request_token='', **kwargs)
    ttl = kwargs.delete(:ttl) || DEFAULT_IFRAME_TTL

    # flatten data if necessary
    if data.values.first.is_a? Enumerable
      data = Hash[data.map {|k,v| [k, (v.is_a?(Enumerable) ? v.first : v)]}]
    end

    missing_keys = []
    [:toopher_sig, :timestamp, :session_token].each do |required_key|
      missing_keys << required_key if data[required_key].nil?
    end
    unless missing_keys.empty?
      raise SignatureValidationError, "Missing required keys: #{missing_keys}"
    end

    if !request_token.empty? && request_token != data[:session_token]
      raise SignatureValidationError, 'Session token does not match expected value!'
    end

    maybe_sig = data.delete(:toopher_sig)
    computed_sig = signature(data)
    if maybe_sig != computed_sig
      raise SignatureValidationError, "Computed signature does not match submitted signature: #{computed_sig} vs #{maybe_sig}"
    end

    if Time.now.to_i - data[:timestamp].to_i >= ttl
      raise SignatureValidationError, 'TTL expired'
    end
    return data
  end

  private

  def signature(data)
    to_sign = URI.encode_www_form(Hash[data.sort]).encode('utf-8')
    secret = @oauth_consumer.secret.encode('utf-8')
    digest = OpenSSL::Digest::Digest.new('sha1')
    hmac = OpenSSL::HMAC.digest(digest, secret, to_sign)
    return Base64.encode64(hmac).chomp.gsub( /\n/, '' )
  end

  def get_oauth_signed_url(url, ttl, **kwargs)
    bools = kwargs.select { |k,v| v.is_a?(TrueClass) || v.is_a?(FalseClass) }
    bools.each do |k,v|
      kwargs[k] = v.to_s.capitalize
    end
    kwargs[:expires] ||= (Time.now.to_i + ttl).to_s
    url = url + '?' + URI.encode_www_form(kwargs)
    res = Net::HTTP::Get.new(@base_url + url)
    return @oauth_consumer.sign!(res, nil)
  end
end

# Abstracts calls to the Toopher OAuth webservice
class ToopherAPI
  # Version of the library
  VERSION = '1.1.0'

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
end

# Contains advanced API methods
class AdvancedApiUsageFactory
  # @!attribute raw
  #   @return [ApiRawRequester] Holds HTTP Request methods.
  attr_accessor :raw

  # @!attribute pairings
  #   @return [Pairings] Holds Pairings methods.
  attr_accessor :pairings

  # @!attribute authentication_requests
  #   @return [AuthenticationRequests] Holds AuthenticationRequests methods.
  attr_accessor :authentication_requests

  # @!attribute users
  #   @return [Users] Holds Users methods.
  attr_accessor :users

  # @!attribute user_terminals
  #   @return [Users] Holds user terminals methods.
  attr_accessor :user_terminals

  # Creates an AdvancedApiUsageFactory for Toopher API advanced methods
  #
  # @param [String] key Your Toopher API Key
  # @param [String] secret Your Toopher API Secret
  # @param [Hash] options OAuth Options hash.
  # @param [string] base_url The base URL to use for the Toopher API
  def initialize(key, secret, options, base_url)
    @raw = ApiRawRequester.new(key, secret, options, base_url)
    @pairings = Pairings.new(@raw)
    @authentication_requests = AuthenticationRequests.new(@raw)
    @users = Users.new(@raw)
    @user_terminals = UserTerminals.new(@raw)
  end
end

# Contains HTTP Request methods
class ApiRawRequester
  # Creates a ApiRawRequester for using HTTP request methods
  #
  # @param [String] key Your Toopher API Key
  # @param [String] secret Your Toopher API Secret
  # @param [Hash] options OAuth Options hash.
  # @param [string] base_url The base URL to use for the Toopher API
  def initialize(key, secret, options, base_url)
    key.empty? and raise ArgumentError, "Toopher consumer key cannot be empty!"
    secret.empty? and raise ArgumentError, "Toopher consumer secret cannot be empty!"

    @oauth_consumer = OAuth::Consumer.new(key, secret)
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
      raw = kwargs.delete(:raw)
      req = Net::HTTP::Get.new(url.path + '?' + URI.encode_www_form(kwargs))
    end
    return request(url, req, raw)
  end

  private
  def request(url, req, raw=nil)
    req['User-Agent'] = "Toopher-Ruby/#{ToopherAPI::VERSION} (Ruby #{RUBY_VERSION})"
    http = Net::HTTP::new(url.host, url.port)
    http.use_ssl = url.port == 443
    req.oauth!(http, @oauth_consumer, nil, @oauth_options)
    res = http.request(req)
    decoded = JSON.parse(res.body) if raw.nil? or res.code.to_i >= 400
    parse_request_error(decoded) if res.code.to_i >= 400
    if raw.nil?
      return decoded
    else
      return res.body
    end
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

# Contains advanced ToopherAPI methods associated with Pairings
class Pairings
  def initialize(raw)
    @raw = raw
  end

  # Check on the status of a previous pairing request
  #
  # @param [String] pairing_id The unique string identifier id returned by a previous pairing request.
  #
  # @return [Pairing] Information about the pairing request
  def get_by_id(pairing_id)
    return Pairing.new(@raw.get('pairings/' + pairing_id))
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

  def get_qr_code_image(api)
    url = 'qr/pairings/' + @id
    return api.advanced.raw.get(url, :raw => true)
  end

  private

  def update(json_obj)
    @id = json_obj['id']
    @enabled = json_obj['enabled']
    @pending = json_obj['pending']
    @user.send(:update, json_obj['user'])
    @raw = json_obj
  end
end

# Contains advanced ToopherAPI methods associated with authentication requests
class AuthenticationRequests
  def initialize(raw)
    @raw = raw
  end

  # Check on the status of a previous authentication request
  #
  # @param [String] authentication_request_id The unique string identifier id returned by a previous authentication request.
  def get_by_id(authentication_request_id)
    return AuthenticationRequest.new(@raw.get('authentication_requests/' + authentication_request_id))
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

  # @!attribute user
  #   @return  [User] Contains information about the User associated with this AuthenticationRequest
  attr_accessor :user

  # @!attribute action
  #   @return  [Action] Contains information about the Action associated with this AuthenticationRequest
  attr_accessor :action

  # @!attribute raw
  #   @return [hash] The raw data returned from the Toopher API
  attr_accessor :raw

  def initialize(json_obj)
    @terminal = UserTerminal.new(json_obj['terminal'])
    @user = User.new(json_obj['user'])
    @action = Action.new(json_obj['action'])
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

  private

  def update(json_obj)
    @id = json_obj['id']
    @pending = json_obj['pending']
    @granted = json_obj['granted']
    @automated = json_obj['automated']
    @reason = json_obj['reason']
    @terminal.send(:update, json_obj['terminal'])
    @user.send(:update, json_obj['user'])
    @action.send(:update, json_obj['action'])
    @raw = json_obj
  end
end

class Action
  # @!attribute id
  #   @return [String] A unique string identifier generated and returned by the Toopher web service that is used to identify this action.
  attr_accessor :id

  # @!attribute name
  #   @return [String] The human recognizable action name associated with the given id.
  attr_accessor :name

  def initialize(json_obj)
    update(json_obj)
  end

  private

  def update(json_obj)
    @id = json_obj['id']
    @name = json_obj['name']
    @raw = json_obj
  end
end

# Contains advanced ToopherAPI methods associated with user terminals
class UserTerminals
  def initialize(raw)
    @raw = raw
  end

  # Check on the status of a user terminal
  #
  # @param [String] terminal_id A unique string identifier generated and returned by the Toopher web service that is used to identify this user terminal.
  def get_by_id(terminal_id)
    return UserTerminal.new(@raw.get('user_terminals/' + terminal_id))
  end

  # Create a new user terminal
  #
  # @param [String] username The human recognizable user name of the user you wish to associate this user terminal.
  # @param [String] terminal_name The human recognizable terminal name.
  def create(username, terminal_name, requester_terminal_id, **kwargs)
    params = {
      :user_name => username,
      :name => terminal_name,
      :name_extra => requester_terminal_id
    }
    params.merge!(kwargs)
    return UserTerminal.new(@raw.post('user_terminals/create', params))
  end

end

# Contains information about a particular user terminal
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

  # @!attribute user
  #   @return [User] Contains information about the User associated with this UserTerminal
  attr_accessor :user

  # @!attribute raw
  #   @return [hash] The raw data returned from the Toopher API
  attr_accessor :raw

  def initialize(json_obj)
    @user = User.new(json_obj['user'])
    update(json_obj)
  end

  def refresh_from_server(api)
    result = api.advanced.raw.get('user_terminals/' + @id)
    update(result)
  end

  private

  def update(json_obj)
    @id = json_obj['id']
    @name = json_obj['name']
    @name_extra = json_obj['name_extra']
    @user.send(:update, json_obj['user'])
    @raw = json_obj
  end
end

# Contains advanced ToopherAPI methods associated with users
class Users
  def initialize(raw)
    @raw = raw
  end

  # Check on the status of a user
  #
  # @param [String] user_id A unique string identifier generated and returned by the Toopher web service that is used to identify this user.
  def get_by_id(user_id)
    return User.new(@raw.get('users/' + user_id))
  end

  # Check on the status of a user
  #
  # @param [String] name The human recognizable user name.
  def get_by_name(username)
    params = { :name => username }
    users = @raw.get('users', params)
    if users.count > 1
      raise ToopherApiError, 'Multiple users with name = #{username}'
    elsif users.count == 0
      raise ToopherApiError, 'No users with name = #{username}'
    end

    return User.new(users[0])
  end

  # Create a new user
  #
  # @param [String] username The human recognizable user name.
  def create(username, **kwargs)
    params = { :name => username }
    params.merge!(kwargs)
    return User.new(@raw.post('users/create', params))
  end
end

# Contains information about a particular User
class User
  # @!attribute id
  #   @return [String] A unique string identifier generated and returned by the Toopher web service that is used to identify this user. It can be used to request status information for the user.
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
    params = { :name => @name }
    api.advanced.raw.post('users/reset', params)
    return true
  end

  private

  def update(json_obj)
    @id = json_obj['id']
    @name = json_obj['name']
    @disable_toopher_auth = json_obj['disable_toopher_auth']
    @raw = json_obj
  end
end