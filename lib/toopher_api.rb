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

# Ruby helper library to generate Toopher iframe requests and validate responses
class ToopherIframe
    DEFAULT_IFRAME_TTL = 300
    IFRAME_VERSION = '2'

    def initialize(key, secret, options, base_url = DEFAULT_BASE_URL)
        key.empty? and raise ArgumentError, "Toopher consumer key cannot be empty!"
        secret.empty? and raise ArgumentError, "Toopher consumer secret cannot be empty!"

        @oauth_options = options.merge(:site => base_url, :scheme => :query_string)
        @oauth_consumer = OAuth::Consumer.new(key, secret, @oauth_options)
        @key = key
        @secret = secret
        @base_url = base_url
    end

    # Generate a URL to retrieve a Toopher Pairing iframe for a given user
    # @param [String] username Unique name that identifies that user. This will be displayed to the user on their mobile device when they pair or authenticate
    # @param [String] reset_email Email address that the user has access to. In case the user has lost or cannot access their mobile device, Toopher will send a reset email to this address.
    # @param [Hash] An optional hash of extra parameters to provide to the API.
    # @return [String] A url that can be used to retrieve the Pairing iframe by the user's browser.
    def get_user_management_url(username, reset_email='', **kwargs)
        ttl = kwargs.delete(:ttl) || DEFAULT_IFRAME_TTL
        params = {
            :username => username,
            :reset_email => reset_email,
        }
        params.merge!(kwargs)
        get_oauth_signed_url('web/manage_user', ttl, params)
    end

    # Generate a URL to retrieve a Toopher Authentication iframe for a given user
    # @param [String] username Unique name that identifies that user. This will be displayed to the user on their mobile device when they pair or authenticate
    # @param [String] reset_email Email address that the user has access to. In case the user has lost or cannot access their mobile device, Toopher will send a reset email to this address.
    # @param [String] request_token Unique token to be returned with the iframe response.
    # @param [String] action_name The name of the action to authenticate; will be shown to the user. If blank, the Toopher API will default the actiont o 'Log In'
    # @param [String] requester_metadata Will be included in the signed data returned with the iframe response.
    # @param [Hash] extras An optional hash of extras to provide to the API.
    # @return [String] A url that can be used to retrieve the Authentication iframe by the user's browser
    def get_authentication_url(username, reset_email='', request_token='', action_name='Log In', requester_metadata='', **kwargs)
        ttl = kwargs.delete(:ttl) || DEFAULT_IFRAME_TTL
        params = {
            :username => username,
            :reset_email => reset_email,
            :action_name => action_name,
            :session_token => request_token,
            :requester_metadata => requester_metadata,
        }
        params.merge!(kwargs)
        get_oauth_signed_url('web/authenticate', ttl, params)
    end

    # Verify the authenticity of data returned from the Toopher iframe
    # @param [Hash] The data returned from the iframe.
    # @param [String] The unique request token.
    # @param [Hash] An optional hash of extras.
    # @return [AuthenticationRequest, Pairing or User] returns AuthenticationRequest, Pairing or User object, depending on data returned from Toopher iframe
    def process_postback(data, request_token='', **kwargs)
        toopher_data = Hash[URI::decode_www_form(data['toopher_iframe_data'])]

        if toopher_data.has_key?('error_code')
            error_code, error_message = Integer(toopher_data['error_code']), toopher_data['error_message']
            if error_code == 704
                raise UserDisabledError, "Error code #{error_code.to_s} : #{error_message}"
            else
                raise ToopherApiError,"Error code #{error_code.to_s} : #{error_message}"
            end
        else
            validate_data(toopher_data, request_token, kwargs)
            api = ToopherApi.new(@key, @secret, @base_url)
            case toopher_data['resource_type']
            when 'authentication_request'
                AuthenticationRequest.new(create_authentication_request_hash(toopher_data), api)
            when 'pairing'
                Pairing.new(create_pairing_hash(toopher_data), api)
            when 'requester_user'
                User.new(create_user_hash(toopher_data), api)
            else
                raise ToopherApiError, "The postback resource type is not valid #{toopher_data['resource_type']}"
            end
        end
    end

    # Evaluate whether AuthenticationRequest has been granted and is not pending
    # @param [Hash] The data returned from the iframe.
    # @param [String] The unique request token.
    # @param [Hash] An optional hash of extras.
    # @return [boolean] true or false indicating if AuthenticationRequest was granted and is not pending
    def is_authentication_granted(data, request_token='', **kwargs)
        begin
            authentication_request = process_postback(data, request_token, **kwargs)
            if authentication_request.instance_of? AuthenticationRequest
                authentication_request.granted && !authentication_request.pending
            else
                false
            end
        rescue UserDisabledError
            true
        rescue
            false
        end
    end

    private

    def validate_data(data, request_token='', **kwargs)
        check_for_missing_keys(data)
        verify_session_token(data['session_token'], request_token)
        check_if_signature_is_expired(data['timestamp'], kwargs)
        validate_signature(data)
    end

    def check_for_missing_keys(data)
        missing_keys = []
        ['toopher_sig', 'timestamp', 'session_token'].each do |required_key|
            missing_keys << required_key if data[required_key].nil?
        end
        if !missing_keys.empty?
            raise SignatureValidationError, "Missing required keys: #{missing_keys.join(',')}"
        end
    end

    def verify_session_token(session_token, request_token)
        if !request_token.empty? && request_token != session_token
            raise SignatureValidationError, 'Session token does not match expected value!'
        end
    end

    def check_if_signature_is_expired(timestamp, kwargs)
        ttl = kwargs.delete(:ttl) || DEFAULT_IFRAME_TTL
        if Time.now.to_i - timestamp.to_i >= ttl
            raise SignatureValidationError, 'TTL expired'
        end
    end

    def validate_signature(data)
        maybe_sig = data.delete('toopher_sig')
        computed_sig = signature(data)
        if maybe_sig != computed_sig
            raise SignatureValidationError, "Computed signature does not match submitted signature: #{computed_sig} vs #{maybe_sig}"
        end
    end

    def signature(data)
        to_sign = URI.encode_www_form(Hash[data.sort]).encode('utf-8')
        secret = @oauth_consumer.secret.encode('utf-8')
        digest = OpenSSL::Digest::Digest.new('sha1')
        hmac = OpenSSL::HMAC.digest(digest, secret, to_sign)
        Base64.encode64(hmac).chomp.gsub( /\n/, '' )
    end

    def create_authentication_request_hash(data)
        {
            'id' => data['id'],
            'pending' => data['pending'] == 'true',
            'granted' => data['granted'] == 'true',
            'automated' => data['automated'] == 'true',
            'reason' => data['reason'],
            'reason_code' => data['reason_code'],
            'terminal' => {
                'id' => data['terminal_id'],
                'name' => data['terminal_name'],
                'requester_specified_id' => data['terminal_requester_specified_id'],
                'user' => {
                    'id' => data['pairing_user_id'],
                    'name' => data['user_name'],
                    'toopher_authentication_enabled' => data['user_toopher_authentication_enabled'] == 'true'
                }
            },
            'user' => {
                'id' => data['pairing_user_id'],
                'name' => data['user_name'],
                'toopher_authentication_enabled' => data['user_toopher_authentication_enabled'] == 'true'
            },
            'action' => {
                'id' => data['action_id'],
                'name' => data['action_name']
            }
        }
    end

    def create_pairing_hash(data)
        {
            'id' => data['id'],
            'enabled' => data['enabled'] == 'true',
            'pending' => data['pending'] == 'true',
            'user' => {
                'id' => data['pairing_user_id'],
                'name' => data['user_name'],
                'toopher_authentication_enabled' => data['user_toopher_authentication_enabled'] == 'true'
            }
        }
    end

    def create_user_hash(data)
        {
            'id' => data['id'],
            'name' => data['name'],
            'toopher_authentication_enabled' => data['toopher_authentication_enabled'] == 'true'
        }
    end

    def get_oauth_signed_url(url, ttl, **kwargs)
        kwargs[:expires] = (Time.now.to_i + ttl).to_s
        kwargs[:v] = IFRAME_VERSION
        url = url + '?' + URI.encode_www_form(kwargs)
        res = Net::HTTP::Get.new(@base_url + url)
        @oauth_consumer.sign!(res, nil)
    end
end

# Abstracts calls to the Toopher OAuth webservice
class ToopherApi
    # Version of the library
    VERSION = '2.0.0'

    # @!attribute advanced
    # @return [AdvancedApiUsageFactory] Holds advanced methods of Toopher API
    attr_accessor :advanced

    # Creates a Toopher API consumer
    # @param [String] key Your Toopher API Key
    # @param [String] secret Your Toopher API Secret
    # @param [Hash] options OAuth Options hash.
    # @param [String] base_url The base URL to use for the Toopher API
    def initialize(key, secret, base_url = DEFAULT_BASE_URL, options = {})
        @advanced = AdvancedApiUsageFactory.new(key, secret, options, base_url, self)
    end

    # Create the pairing between a particular user and their mobile device
    # @param [String] username A human recognizable string which represents the user making the request (usually their username). This is displayed to the user on the mobile app when authenticating.
    # @param [String] phrase_or_num Either the pairing phrase generated by a user's mobile application or the user's phone number. If neither is provided, the pairing will be done by QR code.
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

        response = @advanced.raw.post(url, params)
        Pairing.new(response, self)
    end

    # Authenticate an action with Toopher
    # @param [String] id_or_username The unique string identifier id returned by a previous pairing request or the username of the pairing's user.
    # @param [String] terminal Either the terminal_name, a human recognizable string which represents the terminal from which the user is making the request, or terminal_name_extra ()requester_specified_id), a string to help differentiate identically named terminals. The terminal_name would be displayed to the user on the mobile app when authenticating. If this is not included, then a terminal_id returned from a previous request must be provided (see below). These should be unique values for each different device from which a user connects to your service (as best you can detect).
    # @param [String] action_name Optional action name, defaults to "log in" (displayed to the user)
    # @return [AuthenticationRequest] Information about the authentication request
    def authenticate(id_or_username, terminal_name: '', requester_specified_id: '', action_name: '', **kwargs)
        begin
            UUIDTools::UUID.parse(id_or_username)
            params = { :pairing_id => id_or_username }
        rescue
            params = { :user_name => id_or_username }
        end
        params[:terminal_name] = terminal_name unless terminal_name.empty?
        params[:requester_specified_terminal_id] = requester_specified_id unless requester_specified_id.empty?
        params[:action_name] = action_name unless action_name.empty?
        params.merge!(kwargs)
        response = @advanced.raw.post('authentication_requests/initiate', params)
        AuthenticationRequest.new(response, self)
    end
end

# Contains advanced API methods
class AdvancedApiUsageFactory
    # @!attribute raw
    # @return [ApiRawRequester] Holds HTTP Request methods.
    attr_accessor :raw

    # @!attribute pairings
    # @return [Pairings] Holds Pairings methods.
    attr_accessor :pairings

    # @!attribute authentication_requests
    # @return [AuthenticationRequests] Holds AuthenticationRequests methods.
    attr_accessor :authentication_requests

    # @!attribute users
    # @return [Users] Holds Users methods.
    attr_accessor :users

    # @!attribute user_terminals
    # @return [Users] Holds user terminals methods.
    attr_accessor :user_terminals

    # Creates an AdvancedApiUsageFactory for Toopher API advanced methods
    # @param [String] key Your Toopher API Key
    # @param [String] secret Your Toopher API Secret
    # @param [Hash] options OAuth Options hash.
    # @param [String] base_url The base URL to use for the Toopher API
    def initialize(key, secret, options, base_url, api)
        @raw = ApiRawRequester.new(key, secret, options, base_url)
        @pairings = Pairings.new(api)
        @authentication_requests = AuthenticationRequests.new(api)
        @users = Users.new(api)
        @user_terminals = UserTerminals.new(api)
    end
end

# Contains HTTP Request methods
class ApiRawRequester
    # Creates a ApiRawRequester for using HTTP request methods
    # @param [String] key Your Toopher API Key
    # @param [String] secret Your Toopher API Secret
    # @param [Hash] options OAuth Options hash.
    # @param [String] base_url The base URL to use for the Toopher API
    def initialize(key, secret, options, base_url)
        raise ArgumentError, "Toopher consumer key cannot be empty!" if key.empty?
        raise ArgumentError, "Toopher consumer secret cannot be empty!" if secret.empty?

        @oauth_consumer = OAuth::Consumer.new(key, secret)
        @oauth_options = options
        @base_url = base_url
    end

    def post(endpoint, **kwargs)
        url = URI.parse(@base_url + endpoint)
        req = Net::HTTP::Post.new(url.path)
        req.set_form_data(kwargs)
        request(url, req)
    end

    def get(endpoint, **kwargs)
        url = URI.parse(@base_url + endpoint)
        if kwargs.empty?
            req = Net::HTTP::Get.new(url.path)
        else
            raw = kwargs.delete(:raw)
            req = Net::HTTP::Get.new(url.path + '?' + URI.encode_www_form(kwargs))
        end
        request(url, req, raw)
    end

    private

    def request(url, req, raw=nil)
        req['User-Agent'] = "Toopher-Ruby/#{ToopherApi::VERSION} (Ruby #{RUBY_VERSION})"
        http = Net::HTTP::new(url.host, url.port)
        http.use_ssl = url.port == 443
        @oauth_options ||= {}
        req.oauth!(http, @oauth_consumer, nil, @oauth_options)
        res = http.request(req)
        decoded = JSON.parse(res.body) if raw.nil? or res.code.to_i >= 400
        parse_request_error(decoded) if res.code.to_i >= 400
        raw.nil? ? decoded : res.body
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

# Contains advanced ToopherApi methods associated with Pairings
class Pairings
    def initialize(api)
        @api = api
    end

    # Check on the status of a previous pairing request
    # @param [String] pairing_id The unique string identifier id returned by a previous pairing request.
    # @return [Pairing] Information about the pairing request
    def get_by_id(pairing_id)
        response = @api.advanced.raw.get("pairings/#{pairing_id}")
        Pairing.new(response, @api)
    end
end

# Contains information about a particular pairing request
class Pairing

    # @!attribute id
    # @return [String] A unique identifier generated and returned by the Toopher web service that is used to identify this pairing. It can be used to request status information for the pairing and must be included in subsequent authentication requests for this user.
    attr_accessor :id

    # @!attribute enabled
    # @return [Boolean] Indicates whether or not the pairing has been acknowledged and enabled by the user.
    attr_accessor :enabled

    # @!attribute pending
    # @return [Boolean] Indicates whether or not the pairing is waiting to be acknowledged and enabled or denied by the user.
    attr_accessor :pending

    # @!attribute user
    # @return [User] Contains information about the User associated with this Pairing
    attr_accessor :user

    # @!attribute raw_data
    # @return [hash] The raw data returned from the Toopher API
    attr_accessor :raw_data

    def initialize(json_obj, api)
        @api = api
        @raw_data = json_obj
        @id = json_obj['id']
        @enabled = json_obj['enabled']
        @pending = json_obj['pending']
        @user = User.new(json_obj['user'], api)
    end

    # Update the Pairing with response from the API
    def refresh_from_server
        result = @api.advanced.raw.get("pairings/#{@id}

        ")
        update(result)
    end

    # Retrieve link to allow user to reset the Pairing
    # @param [Hash] kwargs An optional hash of extras to provide to the API.
    # @return [String] A reset link.
    def get_reset_link(**kwargs)
        url = "pairings/#{@id}/generate_reset_link"
        result = @api.advanced.raw.post(url, kwargs)
        result['url']
    end

    # Send reset link to user's reset email
    # @param [String] email The email address where the reset link is sent.
    # @param [Hash] kwargs An optional hash of extras to provide to the API.
    def email_reset_link_to_user(email, **kwargs)
        url = "pairings/#{@id}/send_reset_link"
        params = { :reset_email => email }
        params.merge!(kwargs)
        @api.advanced.raw.post(url, params)
        true
    end

    # Retrieve QR code image for the Pairing
    # @return [String] Image as a String
    def get_qr_code_image
        url = "qr/pairings/#{@id}"
        @api.advanced.raw.get(url, :raw => true)
    end

    private

    def update(json_obj)
        @raw_data = json_obj
        @enabled = json_obj['enabled']
        @pending = json_obj['pending']
        @user.send(:update, json_obj['user'])
    end
end

# Contains advanced ToopherApi methods associated with authentication requests
class AuthenticationRequests
    def initialize(api)
        @api = api
    end

    # Check on the status of a previous authentication request
    # @param [String] authentication_request_id The unique string identifier id returned by a previous authentication request.
    def get_by_id(authentication_request_id)
        response = @api.advanced.raw.get("authentication_requests/#{authentication_request_id}")
        AuthenticationRequest.new(response, @api)
    end
end

# Contains information about a particular authentication request
class AuthenticationRequest

    # @!attribute id
    # @return [String] A unique string identifier generated and returned by the Toopher web service that is used to identify this authentication request. It can be used to request status information for the authentication request.
    attr_accessor :id

    # @!attribute pending
    # @return [Boolean] Indicates whether the request is still pending.
    attr_accessor :pending

    # @!attribute granted
    # @return [Boolean] Indicates whether the request was granted.
    attr_accessor :granted

    # @!attribute automated
    # @return [Boolean] Indicates whether the request was automated.
    attr_accessor :automated

    # @!attribute reason
    # @return  [String] A string which provides additional information about the reason for the authentication outcome (if available).
    attr_accessor :reason

    # @!attribute reason_code
    # @return  [Fixnum] The code associated with the reason of this authentication outcome (if available).
    attr_accessor :reason_code

    # @!attribute terminal
    # @return  [Terminal] Contains information about the Terminal associated with this AuthenticationRequest
    attr_accessor :terminal

    # @!attribute user
    # @return  [User] Contains information about the User associated with this AuthenticationRequest
    attr_accessor :user

    # @!attribute action
    # @return  [Action] Contains information about the Action associated with this AuthenticationRequest
    attr_accessor :action

    # @!attribute raw_data
    # @return [hash] The raw data returned from the Toopher API
    attr_accessor :raw_data

    def initialize(json_obj, api)
        @api = api
        @terminal = UserTerminal.new(json_obj['terminal'], api)
        @user = User.new(json_obj['user'], api)
        @action = Action.new(json_obj['action'])
        update(json_obj)
    end

    # Update the AuthenticationRequest with response from the API
    def refresh_from_server
        result = @api.advanced.raw.get("authentication_requests/#{@id}")
        update(result)
    end

    # Grant the AuthenticationRequest with an OTP
    # @param [String] otp One-time password for the AuthenticationRequest.
    def grant_with_otp(otp, **kwargs)
        url = "authentication_requests/#{@id}/otp_auth"
        params = { :otp => otp }
        params.merge!(kwargs)
        result = @api.advanced.raw.post(url, params)
        update(result)
    end

    private

    def update(json_obj)
        @id = json_obj['id']
        @pending = json_obj['pending']
        @granted = json_obj['granted']
        @automated = json_obj['automated']
        @reason = json_obj['reason']
        @reason_code = json_obj['reason_code']
        @terminal.send(:update, json_obj['terminal'])
        @user.send(:update, json_obj['user'])
        @action.send(:update, json_obj['action'])
        @raw_data = json_obj
    end
end

class Action
    # @!attribute id
    # @return [String] A unique string identifier generated and returned by the Toopher web service that is used to identify this action.
    attr_accessor :id

    # @!attribute name
    # @return [String] The human recognizable action name associated with the given id.
    attr_accessor :name

    # @!attribute raw_data
    # @return [hash] The raw data returned from the Toopher API
    attr_accessor :raw_data

    def initialize(json_obj)
        update(json_obj)
    end

    private

    def update(json_obj)
        @id = json_obj['id']
        @name = json_obj['name']
        @raw_data = json_obj
    end
end

# Contains advanced ToopherApi methods associated with user terminals
class UserTerminals
    def initialize(api)
        @api = api
    end

    # Check on the status of a user terminal
    # @param [String] terminal_id A unique string identifier generated and returned by the Toopher web service that is used to identify this user terminal.
    def get_by_id(terminal_id)
        response = @api.advanced.raw.get("user_terminals/#{terminal_id}")
        UserTerminal.new(response, @api)
    end

    # Create a new user terminal
    # @param [String] username The human recognizable user name of the user you wish to associate this user terminal.
    # @param [String] terminal_name The human recognizable terminal name.
    def create(username, terminal_name, requester_terminal_id, **kwargs)
        params = {
            :user_name => username,
            :name => terminal_name,
            :requester_specified_id => requester_terminal_id
        }
        params.merge!(kwargs)
        response = @api.advanced.raw.post('user_terminals/create', params)
        UserTerminal.new(response, @api)
    end
end

# Contains information about a particular user terminal
class UserTerminal
    # @!attribute id
    # @return [String] A unique string identifier generated and returned by the Toopher web service that is used to identify this user terminal. It can be used to request status information for the user terminal.
    attr_accessor :id

    # @!attribute name
    # @return [String] The human recognizable terminal name associated with the given id.
    attr_accessor :name

    # @!attribute name_extra
    # @return [String] A string to help differentiate identically named terminals.
    attr_accessor :requester_specified_id

    # @!attribute user
    # @return [User] Contains information about the User associated with this UserTerminal
    attr_accessor :user

    # @!attribute raw_data
    # @return [hash] The raw data returned from the Toopher API
    attr_accessor :raw_data

    def initialize(json_obj, api)
        @api = api
        @raw_data = json_obj
        @id = json_obj['id']
        @name = json_obj['name']
        @requester_specified_id = json_obj['requester_specified_id']
        @user = User.new(json_obj['user'], api)
    end

    # Update the UserTerminal with response from the API
    def refresh_from_server
        result = @api.advanced.raw.get("user_terminals/#{@id}")
        update(result)
    end

    private

    def update(json_obj)
        @raw_data = json_obj
        @name = json_obj['name']
        @requester_specified_id = json_obj['requester_specified_id']
        @user.send(:update, json_obj['user'])
    end
end

# Contains advanced ToopherApi methods associated with users
class Users
    def initialize(api)
        @api = api
    end

    # Check on the status of a user
    # @param [String] user_id A unique string identifier generated and returned by the Toopher web service that is used to identify this user.
    def get_by_id(user_id)
        response = @api.advanced.raw.get("users/#{user_id}")
        User.new(response, @api)
    end

    # Check on the status of a user
    # @param [String] name The human recognizable user name.
    def get_by_name(username)
        params = { :name => username }
        users = @api.advanced.raw.get('users', params)
        if users.count > 1
            raise ToopherApiError, "Multiple users with name = #{username}"
        elsif users.count == 0
            raise ToopherApiError, "No users with name = #{username}"
        end

        User.new(users[0], @api)
    end

    # Create a new user
    # @param [String] username The human recognizable user name.
    def create(username, **kwargs)
        params = { :name => username }
        params.merge!(kwargs)
        response = @api.advanced.raw.post('users/create', params)
        User.new(response, @api)
    end
end

# Contains information about a particular User
class User
    # @!attribute id
    # @return [String] A unique string identifier generated and returned by the Toopher web service that is used to identify this user. It can be used to request status information for the user.
    attr_accessor :id

    # @!attribute name
    # @return [String] The human recognizable user name associated with the given id.
    attr_accessor :name

    # @!attribute toopher_authentication_enabled
    # @return [Boolean] Whether or not this user has Toopher authentication enabled or disabled.
    attr_accessor :toopher_authentication_enabled

    # @!attribute raw_data
    # @return [hash] The raw data returned from the Toopher API
    attr_accessor :raw

    def initialize(json_obj, api)
        @api = api
        @raw_data = json_obj
        @id = json_obj['id']
        @name = json_obj['name']
        @toopher_authentication_enabled = json_obj['toopher_authentication_enabled']
    end

    # Update the User with response from the API
    def refresh_from_server
        result = @api.advanced.raw.get("users/#{@id}")
        update(result)
    end

    # Enable Toopher authentication for the User
    def enable_toopher_authentication
        url = "users/#{@id}"
        response = @api.advanced.raw.post(url, :toopher_authentication_enabled => true)
        update(response)
    end

    # Disable Toopher authentication for the User
    def disable_toopher_authentication
        url = "users/#{@id}"
        response = @api.advanced.raw.post(url, :toopher_authentication_enabled => false)
        update(response)
    end

    # Remove all pairings for the User
    def reset
        params = { :name => @name }
        @api.advanced.raw.post('users/reset', params)
        true
    end

    private

    def update(json_obj)
        @raw_data = json_obj
        @name = json_obj['name']
        @toopher_authentication_enabled = json_obj['toopher_authentication_enabled']
    end
end
