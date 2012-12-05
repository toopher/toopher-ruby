#!/usr/bin/ruby
require_relative '../lib/toopher_api'

puts 'enter consumer key, or [ENTER] to use $TOOPHER_CONSUMER_KEY'
key = gets
key.chomp!
puts 'enter consumer secret, or [ENTER] to use $TOOPHER_CONSUMER_SECRET'
secret = gets
secret.chomp!

toopher = ToopherAPI.new(key, secret)

puts 'STEP 1: Pair device'
puts 'enter pairing phrase:'
phrase = gets
phrase.chomp!
puts 'enter user name:'
user = gets
user.chomp!

pairing = toopher.pair(phrase, user)

while(!pairing['enabled'])
  puts 'waiting for authorization...'
  sleep(1)
  pairing = toopher.get_pairing_status(pairing['id'])
end

puts 'paired successfully!'

puts 'STEP 2: Authenticate login'
puts 'enter terminal name:'
terminal_name = gets;
terminal_name.chomp!
puts 'enter action name, or [ENTER] for none:'
while (true)
  action = gets;
  action.chomp!

  puts 'sending authentication request...'
  auth = toopher.authenticate(pairing['id'], terminal_name, action)

  while(auth['pending'])
    puts 'waiting for authentication...'
    sleep(1)
    auth = toopher.get_authentication_status(auth['id'])
  end

  puts "Successfully authorized action '" + action + "'.  Enter another action to authorize again, or [Ctrl-C] to exit"
end

