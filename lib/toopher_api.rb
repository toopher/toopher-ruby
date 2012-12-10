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

class ToopherApiError < StandardError
end

class ToopherAPI

  DEFAULT_BASE_URL = 'https://toopher-api.appspot.com/v1/'

  def initialize(key,secret,options={}, base_url = DEFAULT_BASE_URL)
    consumer_key = key
    consumer_secret = secret

    consumer_key.empty? and raise ArgumentError, "Toopher consumer key cannot be empty!"
    consumer_secret.empty? and raise ArgumentError, "Toopher consumer secret cannot be empty!"

    @base_url = base_url
    @oauth_consumer = OAuth::Consumer.new(consumer_key, consumer_secret)
    @oauth_options = options
  end

  def pair(pairing_phrase, user_name)
    return make_pair_response(post('pairings/create', {
      'pairing_phrase' => pairing_phrase,
      'user_name' => user_name
    }))
  end

  def get_pairing_status(pairing_request_id)
    return make_pair_response(get('pairings/' + pairing_request_id))
  end

  def authenticate(pairing_id, terminal_name, action_name = '')
    parameters = {
      'pairing_id' => pairing_id,
      'terminal_name' => terminal_name
    }
    action_name.empty? or (parameters['action_name'] = action_name)
    return make_auth_response(post('authentication_requests/initiate', parameters))
  end

  def get_authentication_status(authentication_request_id)
    return make_auth_response(get('authentication_requests/' + authentication_request_id))
  end

  private
  def make_pair_response(result)
    return {
      'id' => result['id'],
      'enabled' => result['enabled'],
      'user_id' => result['user']['id'],
      'user_name' => result['user']['name']
    }
  end
  def make_auth_response(result)
    return {
      'id' => result['id'],
      'pending' => result['pending'],
      'granted' => result['granted'],
      'automated' => result['automated'],
      'reason' => result['reason'],
      'terminal_id' => result['terminal']['id'],
      'terminal_name' => result['terminal']['name']
    }
  end
  def post(endpoint, parameters)
    url = URI.parse(@base_url + endpoint)
    req = Net::HTTP::Post.new(url.path)
    req.set_form_data(parameters)
    return request(url, req)
  end

  def get(endpoint)
    url = URI.parse(@base_url + endpoint)
    req = Net::HTTP::Get.new(url.path)
    return request(url, req)
  end

  def request(url, req)
    http = Net::HTTP::new(url.host, url.port)
    http.use_ssl = url.port == 443
    req.oauth!(http, @oauth_consumer, nil, @oauth_options)
    res = http.request(req)
    decoded = JSON.parse(res.body)
    if(decoded.has_key?("error_code"))
      raise ToopherApiError, "Error code " + decoded['error_code'].to_s + ": " + decoded['error_message']
    end
    return decoded
  end
end
