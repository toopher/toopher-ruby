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

require 'net/http'
require 'net/https'
require 'uri'
require 'json'
require 'oauth'

class ToopherAPI

  def initialize(key='',secret='',options={}, base_url = '')
    consumer_key = key.empty? ? ENV['TOOPHER_CONSUMER_KEY'] : key
    consumer_secret = secret.empty? ? ENV['TOOPHER_CONSUMER_SECRET'] : secret

    consumer_key.empty? and raise ArgumentError, "Toopher consumer key not supplied (try defining \$TOOPHER_CONSUMER_KEY)"
    consumer_secret.empty? and raise ArgumentError, "Toopher consumer secret not supplied (try defining \$TOOPHER_CONSUMER_SECRET)"

    @base_url = base_url.empty? ? 'https://toopher-api.appspot.com/v1/' : base_url
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
    puts 'make_pair_response: ' + result.inspect
    return {
      'id' => result['id'],
      'enabled' => result['enabled'] == 'true',
      'user_id' => result['user']['id'],
      'user_name' => result['user']['name']
    }
  end
  def make_auth_response(result)
    return {
      'id' => result['id'],
      'pending' => result['pending'] == 'true',
      'granted' => result['granted'] == 'true',
      'automated' => result['automated'] == 'true',
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
    return JSON.parse(res.body)
  end
end
