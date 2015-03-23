#!/usr/bin/ruby
require_relative '../lib/toopher_api'

DEFAULT_USERNAME = 'demo@toopher.com'
DEFAULT_TERMINAL_NAME = 'my computer'

def initialize_api
    key = ENV['TOOPHER_CONSUMER_KEY']
    secret = ENV['TOOPHER_CONSUMER_SECRET']
    if key.nil? or secret.nil?
        print_text_with_underline('Setup Credentials')
        puts 'Enter your requester credential details (from https://dev.toopher.com).'
        puts('Hint: Set the TOOPHER_CONSUMER_SECRET and TOOPHER_CONSUMER_SECRET environment variables to avoid this prompt.')
    end
    while key.nil? or key.empty?
        print 'TOOPHER_CONSUMER_KEY: '
        STDOUT.flush
        key = gets
        key.chomp!
    end
    while secret.nil? or secret.empty?
        print 'TOOPHER_CONSUMER_SECRET: '
        STDOUT.flush
        secret = gets
        secret.chomp!
    end

    url = ENV['TOOPHER_BASE_URL']
    api = ToopherApi.new(key, secret, url)
end

def pair_device_with_toopher(api)
    while true
        print_text_with_underline('STEP 1: Pair requester with phone')
        puts 'Pairing phrases are generated on the mobile app.'
        print 'Enter pairing phrase: '
        phrase = gets
        phrase.chomp!
        while phrase.empty?
            print 'Please enter a pairing phrase to continue'
            phrase = gets
            phrase.chomp!
        end

        print "Enter a username for this pairing [#{DEFAULT_USERNAME}]: "
        username = gets
        username.chomp!
        if username.empty?
            username = DEFAULT_USERNAME
        end

        puts 'Sending pairing request...'

        begin
            pairing = api.pair(username, phrase)
            break
        rescue Exception => e
            puts "The pairing phrase was not accepted (Reason: #{e.message})"
        end
    end

    while true
        puts
        puts ('Authorize pairing on phone and then press return to continue.')
        gets.chomp
        puts 'Checking status of pairing request...'
        begin
            pairing.refresh_from_server
            if pairing.pending
                puts 'The pairing has not been authorized by the phone yet.'
            elsif pairing.enabled
                puts 'Pairing complete!'
                break
            else
                puts 'The pairing has been denied.'
                break
            end
        rescue Exception => e
            puts "Could not check pairing status (Reason: #{e.message})"
        end
    end

    pairing
end

def authenticate_with_toopher(api, pairing)
    while true
        print_text_with_underline('STEP 2: Authenticate login')
        print "Enter a terminal name for this authentication request [#{DEFAULT_TERMINAL_NAME}]: "
        terminal_name = gets;
        terminal_name.chomp!

        if terminal_name.empty?
            terminal_name = DEFAULT_TERMINAL_NAME
        end

        puts 'Sending authentication request...'

        begin
            auth_request = api.authenticate(pairing.id, terminal_name: terminal_name)
        rescue Exception => e
            puts "Error initiating authentication (Reason: #{e.message})"
            break
        end

        while true
            puts
            puts ('Respond to authentication request on phone and then press return to continue.')
            gets.chomp
            puts 'Checking status of authentication request...'
            begin
                auth_request.refresh_from_server
            rescue Exception => e
                puts "Could not check authentication request status (Reason: #{e.message})"
            end

            if auth_request.pending
                puts 'The authentication request has not received a response from the phone yet.'
            else
                automation = auth_request.automated ? 'automatically ' : ''
                result = auth_request.granted ? 'granted' : 'denied'
                puts 'The request was ' + automation + result + "!"
                break
            end
        end
        
        print "Press return to authenticate again, or [Ctrl-C] to exit. "
        gets.chomp
    end
end

def print_text_with_underline(text, char='-')
    puts
    puts text
    puts char * 50
end

def demo
    print_text_with_underline('Toopher Library Demo', '=')
    api = initialize_api
    pairing = pair_device_with_toopher(api)
    if pairing.enabled
        authenticate_with_toopher(api, pairing)
    end
end

demo
