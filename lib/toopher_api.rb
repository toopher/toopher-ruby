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

  # Creates a Toopher API consumer
  #
  # @param [String] key Your Toopher API Key
  # @param [String] secret Your Toopher API Secret
  # @param [Hash] options OAuth Options hash.
  # @param [string] base_url The base URL to use for the Toopher API
  def initialize(key, secret, options = {}, base_url = DEFAULT_BASE_URL)
    consumer_key = key
    consumer_secret = secret

    consumer_key.empty? and raise ArgumentError, "Toopher consumer key cannot be empty!"
    consumer_secret.empty? and raise ArgumentError, "Toopher consumer secret cannot be empty!"

    @base_url = base_url
    @oauth_consumer = OAuth::Consumer.new(consumer_key, consumer_secret)
    @oauth_options = options
  end

  # Create the pairing between a particular user and their mobile device
  #
  # @param [String] pairing_phrase The pairing phrase generated by a user's mobile application.
  # @param [String] user_name A human recognizable string which represents the user making the request (usually their username). This is displayed to the user on the mobile app when authenticating.
  #
  # @return [PairingStatus] Information about the pairing request
  def pair(pairing_phrase, user_name, options = {})
    return PairingStatus.new(post('pairings/create', {
      'pairing_phrase' => pairing_phrase,
      'user_name' => user_name
    }.merge(options)))
  end

  # Check on the status of a previous pairing request
  #
  # @param [String] pairing_request_id The unique string identifier id returned by a previous pairing request.
  #
  # @return [PairingStatus] Information about the pairing request
  def get_pairing_status(pairing_request_id)
    return PairingStatus.new(get('pairings/' + pairing_request_id))
  end

  # Authenticate an action with Toopher
  #
  # @param [String] pairing_id The unique string identifier id returned by a previous pairing request.
  # @param [String] terminal_name A human recognizable string which represents the terminal from which the user is making the request. This is displayed to the user on the mobile app when authenticating. If this is not included, then a terminal_id returned from a previous request must be provided (see below). These should be unique values for each different device from which a user connects to your service (as best you can detect).
  # @param [String] action_name Optional action name, defaults to "log in" (displayed to the user)
  #
  # @return [AuthenticationStatus] Information about the authentication request
  def authenticate(pairing_id, terminal_name = '', action_name = '', options = {})
    parameters = {
      'pairing_id' => pairing_id,
      'terminal_name' => terminal_name
    }
    action_name.empty? or (parameters['action_name'] = action_name)
    return AuthenticationStatus.new(post('authentication_requests/initiate', parameters.merge(options)))
  end

  # Check on the status of a previous authentication request
  #
  # @param [String] authentication_request_id The unique string identifier id returned by a previous authentication request.
  def get_authentication_status(authentication_request_id)
    return AuthenticationStatus.new(get('authentication_requests/' + authentication_request_id))
  end

  def authenticate_by_user_name(user_name, terminal_name_extra, action_name = '', options = {})
    options[:user_name] = user_name
    options[:terminal_name_extra] = terminal_name_extra
    return authenticate('', '', action_name, options)
  end

  def create_user_terminal(user_name, terminal_name, requester_terminal_id)
    uri = 'user_terminals/create'
    params = {:user_name => user_name,
              :name => terminal_name,
              :name_extra => requester_terminal_id}
    result = post(uri, params)
  end

  def set_enable_toopher_for_user(user_name, enabled)
    uri = 'users'
    users = get(uri, {"name" => user_name})
    if users.count > 1
      raise ToopherApiError, "Multiple users with name = #{user_name}"
    elsif users.count == 0
      raise ToopherApiError, "No users with name = #{user_name}"
    end
    uri = 'users/' + users[0]['id']
    params = {'disable_toopher_auth' => !enabled}
    result = post(uri, params)
  end

  private
  def post(endpoint, parameters)
    url = URI.parse(@base_url + endpoint)
    req = Net::HTTP::Post.new(url.path)
    req.set_form_data(parameters)
    return request(url, req)
  end

  def get(endpoint, parameters = {})
    url = URI.parse(@base_url + endpoint)
    if parameters.empty?
      req = Net::HTTP::Get.new(url.path)
    else
      req = Net::HTTP::Get.new(url.path + '?' + URI.encode_www_form(parameters))
    end
    return request(url, req)
  end

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
class PairingStatus

  # @!attribute id
  #   @return [String] A unique identifier generated and returned by the Toopher web service that is used to identify this pairing. It can be used to request status information for the pairing and must be included in subsequent authentication requests for this user.
  attr_accessor :id

  # @!attribute enabled
  #   @return [Boolean] Indicates whether or not the pairing has been acknowledged and enabled by the user.
  attr_accessor :enabled

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
    @id = json_obj['id']
    @enabled = json_obj['enabled']
    @user_id = json_obj['user']['id']
    @user_name = json_obj['user']['name']
    @raw = json_obj
  end
end

# Contains information about a particular authentication request
class AuthenticationStatus

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

  # @!attribute terminal_id
  #   @return  [String]A unique string identifier generated and returned by the Toopher web service for a given terminal.
  attr_accessor :terminal_id

  # @!attribute terminal_name
  #   @return [String] The human recognizable terminal name associated with the given id.
  attr_accessor :terminal_name

  # @!attribute raw
  #   @return [hash] The raw data returned from the Toopher API
  attr_accessor :raw

  def initialize(json_obj)
    @id = json_obj['id']
    @pending = json_obj['pending']
    @granted = json_obj['granted']
    @automated = json_obj['automated']
    @reason = json_obj['reason']
    @terminal_id = json_obj['terminal']['id']
    @terminal_name = json_obj['terminal']['name']
    @raw = json_obj
  end
end
