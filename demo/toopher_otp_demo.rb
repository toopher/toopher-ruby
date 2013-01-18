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

base_url = ENV['TOOPHER_BASE_URL']
if base_url.nil? or base_url.empty?
  base_url = nil
end
toopher = ToopherAPI.new(key, secret, {}, base_url)

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

  while(auth.pending)
    puts 'Enter OTP:'
    otp = gets
    otp.chomp!
    auth = toopher.send_authentication_otp(auth.id, otp)
  end

  puts "Successfully authorized action '" + action + "'.  Enter another action to authorize again, or [Ctrl-C] to exit"
end

