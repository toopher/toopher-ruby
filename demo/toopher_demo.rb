#!/usr/bin/ruby
require_relative '../lib/toopher_api'

key = ENV['TOOPHER_CONSUMER_KEY']
secret = ENV['TOOPHER_CONSUMER_SECRET']
if key.nil? or secret.nil?
  puts 'enter consumer credentials (set environment variables to prevent prompting):'
end
while key.nil? or key.empty?
  print 'TOOPHER_CONSUMER_KEY='
  STDOUT.flush
  key = gets
  key.chomp!
end
while secret.nil? or secret.empty?
  print 'TOOPHER_CONSUMER_SECRET='
  STDOUT.flush
  secret = gets
  secret.chomp!
end

url = ENV['TOOPHER_BASE_URL']
puts 'using base url = ' + url
toopher = ToopherApi.new(key, secret, url)

puts 'STEP 1: Pair device'
puts 'enter pairing phrase:'
phrase = gets
phrase.chomp!
puts 'enter user name:'
user = gets
user.chomp!

pairing = toopher.pair(user, phrase)

while(!pairing.enabled)
  puts 'waiting for authorization...'
  sleep(1)
  pairing.refresh_from_server(toopher)
end

puts 'paired successfully!'

puts 'STEP 2: Authenticate login'
puts 'enter terminal name:'
terminal_name = gets;
terminal_name.chomp!
puts 'enter action name, or press [ENTER] for the default action ("log in"):'
while (true)
  action = gets;
  action.chomp!

  puts 'sending authentication request...'
  auth_request = toopher.authenticate(pairing.id, terminal_name, action)

  while(auth_request.pending)
    puts 'waiting for authentication...'
    sleep(1)
    auth_request.refresh_from_server(toopher)
  end

  automation = auth_request.automated ? 'automatically ' : ''
  result = auth_request.granted ? 'granted' : 'denied'
  puts 'The request was ' + automation + result + "! Enter another action to authorize again, or [Ctrl-C] to exit"
end

