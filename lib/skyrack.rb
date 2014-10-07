
#require 'pathname'
#require Pathname.new(__FILE__).realpath.expand_path.parent.join('lib')
binbase = __FILE__
while File.symlink?(binbase)
  binbase = File.expand_path(File.readlink(binbase), File.dirname(binbase))
end
$:.unshift(File.expand_path(File.join(File.dirname(binbase), 'lib', 'skyrack')))

require 'functions'
require 'gadget'
require 'gadget_db'
require 'instr'
require 'payload'
require 'roper'
require 'version'

module Skyrack
  # your code here
end
