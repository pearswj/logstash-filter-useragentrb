Gem::Specification.new do |s|
  s.name          = 'logstash-filter-useragentrb'
  s.version       = '0.1.0'
  s.licenses      = ['MIT']
  s.summary       = 'A pure ruby logstash filter for parsing user agent strings.'
  # s.description   = 'TODO: Write a longer description or delete this line.'
  s.homepage      = 'https://github.com/mcneel/logstash-filter-useragentrb'
  s.authors       = ['Will Pearson']
  s.email         = 'will@mcneel.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency "user_agent_parser"
  s.add_development_dependency 'logstash-devutils'
end
