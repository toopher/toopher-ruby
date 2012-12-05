Gem::Specification.new do |s|
  s.name          = 'toopher_api'
  s.version       = '1.0.0'
  s.date          = '2012-12-05'
  s.summary       = 'Interface to the toopher.com authentication api'
  s.description   = 'Synchronous interface to the toopher.com authentication api.  Use em_toopher_api instead if calling from an EventMachine loop'
  s.authors       = ['Toopher, Inc.']
  s.email         = 'support@toopher.com'
  s.files         = ['lib/toopher_api.rb']
  s.homepage      = 'http://toopher.org'
  
  s.add_dependency('oauth', '>= 0.4.7')
  s.add_dependency('json', '>= 1.7.5')

  s.add_development_dependency('webmock', '>= 1.9.0')
end
