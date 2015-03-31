# ToopherRuby [![Build Status](https://travis-ci.org/toopher/toopher-ruby.png?branch=master)](https://travis-ci.org/toopher/toopher-ruby)

ToopherRuby is a Toopher API library that simplifies the task of interfacing with the Toopher API from Ruby code. This project wrangles all the dependency libraries and handles the required OAuth and JSON functionality so you can focus on just using the API.

### Ruby Version
\>=2.0.0

### Documentation
Make sure you visit [https://dev.toopher.com](https://dev.toopher.com) to get acquainted with the Toopher API fundamentals.  The documentation there will tell you the details about the operations this API wrapper library provides.

## ToopherApi Workflow

### Step 1: Pair
Before you can enhance your website's actions with Toopher, your customers will need to pair their mobile device's Toopher app with your website.  To do this, they generate a unique pairing phrase from within the app on their mobile device.  You will need to prompt them for a pairing phrase as part of the Toopher enrollment process.  Once you have a pairing phrase, just send it to the Toopher web service along with your requester credentials and we'll return a pairing ID that you can use whenever you want to authenticate an action for that user.

```ruby
require 'toopher_api'

# Create an API object using your credentials
api = ToopherApi.new('<your consumer key>', '<your consumer secret>')

# Step 1 - Pair with their mobile device's Toopher app
pairing = api.pair('username@yourservice.com', 'pairing phrase')
```

### Step 2: Authenticate
You have complete control over what actions you want to authenticate using Toopher (logging in, changing account information, making a purchase, etc.). Just send us the username or pairing ID and we'll make sure they actually want it to happen. You can also choose to provide the following optional parameters: terminal name, requester specified ID and action name (*default: 'Log in'*).

```ruby
# Step 2 - Authenticate a log in
auth_status = api.authenticate('username@yourservice.com', terminal_name: 'my computer')

# Once they've responded you can then check the status
auth_status.refresh_from_server
if auth_status.granted
    # Success!
end
```

## ToopherIframe Workflow

### Step 1: Embed a request in an IFRAME
1. Generate an authentication URL by providing a username.
2. Display a webpage to your user that embeds this URL within an `<iframe>` element.

```ruby
require 'toopher_api'

# Create an API object using your credentials
iframe_api = ToopherIframe.new('<your consumer key>', '<your consumer secret>')

auth_iframe_url = iframe_api.get_authentication_url('username@yourservice.com')

# Add an <iframe> element to your HTML:
# <iframe id="toopher_iframe" src=auth_iframe_url />
```

### Step 2: Validate the postback data

The simplest way to validate the postback data is to call `is_authentication_granted` to check if the authentication request was granted.

```ruby
# Retrieve the postback data as a string from POST paramter 'iframe_postback_data'

# Returns boolean indicating if authentication request was granted by user
authentication_request_granted = iframe_api.is_authentication_granted(postback_data)

if authentication_request_granted
    # Success!
end
```

### Handling Errors
If any request runs into an error a `ToopherApiError` will be raised with more details on what went wrong.


### Demo
Check out `demo/toopher_demo.rb` for an example program that walks you through the whole process!  Simply run the command below:
```shell
$ ruby demo/toopher_demo.ruby
```

## Contributing
### Dependencies
To install ToopherRuby run:
```shell
$ gem install toopher_api
```

This library uses the oauth and json gems.  'gem' will make sure these are installed.  To install manually run:
```shell
$ gem install oauth
$ gem install json
```

Additionally, you will need the webmock library if you wish to run the unit tests:
```shell
$ gem install webmock
```


### Known Issues
When running the demo code with ruby 2.0.0, you might receive an OpenSSL error stating that the certificate verification failed.  This is a known issue with rubygems. Refer to [railsapps](http://railsapps.github.com/openssl-certificate-verify-failed.html) for a discussion of the problem and an exhaustive list of potential workarounds.  Here's what worked for us, using rvm and homebrew:
```shell
$ rvm remove 2.0.0
$ brew install openssl
$ rvm install 2.0.0 --with-openssl-dir=`brew --prefix openssl`
```

### Tests
To run the tests enter:
```shell
$ rake test
```

## License
ToopherRuby is licensed under the MIT License. See LICENSE.txt for the full text.
