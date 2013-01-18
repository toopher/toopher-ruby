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

toopher = ToopherAPI.new(key, secret)

puts 'STEP 1: Pair device'
puts 'enter pairing phrase:'
phrase = gets
phrase.chomp!
puts 'enter user name:'
user = gets
user.chomp!

pairing = toopher.pair(phrase, user)

while(!pairing.enabled)
  puts 'waiting for authorization...'
  sleep(1)
  pairing = toopher.get_pairing_status(pairing.id)
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
  auth = toopher.authenticate(pairing.id, terminal_name, action)

  puts 'hit [ENTER] to sent cancellation request'
  gets
  puts 'Cancel returned: ' + toopher.cancel_authentication_request(auth.id).to_s

  puts "Enter another action to authorize again, or [Ctrl-C] to exit"
end
