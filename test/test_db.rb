binbase = __FILE__
while File.symlink?(binbase)
  binbase = File.expand_path(File.readlink(binbase), File.dirname(binbase))
end
$:.unshift(File.expand_path(File.join(File.dirname(binbase), '../', 'lib')))

require 'test/unit'
require 'skyrack/gadget_db'
require 'tempfile'

class TestInstr < Test::Unit::TestCase
  def setup
    Instr.cpu = Metasm::Ia32.new
  end

  def test_open_and_create_db
    assert true
  end
end
