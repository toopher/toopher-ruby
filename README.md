# ToopherAPI Ruby Client

[![Build Status](https://travis-ci.org/toopher/toopher-ruby.png?branch=master)](https://travis-ci.org/toopher/toopher-ruby)

#### Introduction
ToopherAPI Ruby Client simplifies the task of interfacing with the Toopher API from Ruby code.  To use, just `gem install toopher_api` and you'll be ready to go.

#### Learn the Toopher API
Make sure you visit [http://dev.toopher.com](http://dev.toopher.com) to get acquainted with the Toopher API fundamentals.  The documentation there will tell you the details about the operations this API wrapper library provides.

#### OAuth Authentication

The first step to accessing the Toopher API is to sign up for an account at the development portal (http://dev.toopher.com) and create a "requester". When that process is complete, your requester is issued OAuth 1.0a credentials in the form of a consumer key and secret. Your key is used to identify your requester when Toopher interacts with your customers, and the secret is used to sign each request so that we know it is generated by you.  This library properly formats each request with your credentials automatically.

#### The Toopher Two-Step
Interacting with the Toopher web service involves two steps: pairing, and authenticating.

##### Pair
Before you can enhance your website's actions with Toopher, your customers will need to pair their phone's Toopher app with your website.  To do this, they generate a unique, nonsensical "pairing phrase" from within the app on their phone.  You will need to prompt them for a pairing phrase as part of the Toopher enrollment process.  Once you have a pairing phrase, just send it to the Toopher API along with your requester credentials and we'll return a pairing ID that you can use whenever you want to authenticate an action for that user.

##### Authenticate
You have complete control over what actions you want to authenticate using Toopher (for example: logging in, changing account information, making a purchase, etc.).  Just send us the user's pairing ID, a name for the terminal they're using, and a description of the action they're trying to perform and we'll make sure they actually want it to happen.

#### Librarified
This library makes it super simple to do the Toopher two-step.  Check it out:

```ruby
require 'toopher_api'

# Create an API object using your credentials
toopher = ToopherAPI.new("key", "secret")

# Step 1 - Pair with their phone's Toopher app
pairing = toopher.pair("pairing phrase", "username@yourservice.com")

# Step 2 - Authenticate a log in
auth_status = toopher.authenticate(pairing.id, 'my computer')

# Once they've responded you can then check the status
while auth_status.pending
    auth_status = toopher.get_authentication_status(auth_status.id)
    sleep(1)
end

if auth_status.granted
    # Success!
else
    # user declined the authorization!
end
```

#### Dependencies
'ToopherAPI Ruby Client depends on the oauth and json gems.  'gem' will make sure these are installed.  To install manually:
```shell
$ gem install oauth
$ gem install json
```
Additionally, you will need the webmock library if you wish to run the unit tests:
```shell
$ gem install webmock
```
#### Handling Errors
If any request runs into an error a `ToopherApiError` will be raised with more details on what went wrong.

#### Example code
Check out demo/toopher_demo.rb for an example program that walks you through the whole process!  Simply execute the script as follows:
```shell
$ ruby demo/toopher_demo.ruby
```
To avoid being prompted for your Toopher API key and secret, you can define them in the $TOOPHER_CONSUMER_KEY and $TOOPHER_CONSUMER_SECRET environment variables

#### Zero-Storage usage option
Requesters can choose to integrate the Toopher API in a way does not require storing any per-user data such as Pairing ID and Terminal ID - all of the storage
is handled by the Toopher API Web Service, allowing your local database to remain unchanged.  If the Toopher API needs more data, it will raise an exception with a specific
error string that allows your code to respond appropriately.

```ruby
begin
    # optimistically try to authenticate against Toopher API with username and a Terminal Identifier
    # Terminal Identifer is typically a randomly generated secure browser cookie.  It does not
    # need to be human-readable
    auth = api.authenticate_by_user_name(user_name, terminal_identifier)

    # if you got here, everything is good!  poll the auth request status as described above
    # there are four distinct errors ToopherAPI can return if it needs more data
rescue UserDisabledError
    # you have marked this user as disabled in the Toopher API.
rescue UnknownUserError
    # This user has not yet paired a mobile device with their account.  Pair them
    # using api.pair() as described above, then re-try authentication
rescue UnknownTerminalError
    # This user has not assigned a "Friendly Name" to this terminal identifier.
    # Prompt them to enter a terminal name, then submit that "friendly name" to
    # the Toopher API:
    #   api.create_user_terminal(user_name, terminal_friendly_name, terminal_identifier)
    # Afterwards, re-try authentication
rescue PairingDeactivatedError
    # this user does not have an active pairing,
    # typically because they deleted the pairing.  You can prompt
    # the user to re-pair with a new mobile device.
end
```

#### Known Issues / Workarouds
When running the demo code with ruby 1.9.3, you might receive an OpenSSL error stating that the certificate verify failed.  This is a known issue with rubygems, refer to [this railsapps page](http://railsapps.github.com/openssl-certificate-verify-failed.html) for a discussion of the problem and an exhaustive list of potential workarounds.  Here's what worked for us (using rvm and homebrew):
```shell
$ rvm remove 1.9.3
$ brew install openssl
$ rvm install 1.9.3 --with-openssl-dir=`brew --prefix openssl`
```

#### Tests
To run all unit tests:
```shell
$ rake test   # (or just 'rake')
```

