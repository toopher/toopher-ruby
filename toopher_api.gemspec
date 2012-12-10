Gem::Specification.new do |s|
  s.name          = 'toopher_api'
  s.version       = '1.0.2'
  s.date          = '2012-12-05'
  s.summary       = 'Interface to the toopher.com authentication api'
  s.description   = 'Synchronous interface to the toopher.com authentication api.'
  s.authors       = ['Toopher, Inc.']
  s.email         = 'support@toopher.com'
  s.files         = ['Rakefile', 'lib/toopher_api.rb', 'test/test_toopher_api.rb', 'demo/toopher_demo.rb']
  s.homepage      = 'http://dev.toopher.com'
  
  s.add_dependency('oauth', '>= 0.4.7')
  s.add_dependency('json', '>= 1.7.5')

  s.add_development_dependency('webmock', '>= 1.9.0')
  s.add_development_dependency('yard', '>= 0.8.3')
end
