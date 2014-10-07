binbase = __FILE__
while File.symlink?(binbase)
  binbase = File.expand_path(File.readlink(binbase), File.dirname(binbase))
end
$:.unshift(File.expand_path(File.join(File.dirname(binbase), '../', 'lib')))

require 'test/unit'
require 'skyrack/instr'

class TestInstr < Test::Unit::TestCase

  def setup
    Instr.cpu = Metasm::Ia32.new
  end

  def test_instr_decode
    nop = Instr.new("\x90".force_encoding("ASCII-8BIT"))
    assert_equal nop.bin.force_encoding("ASCII-8BIT"), "\x90".force_encoding("ASCII-8BIT")
    assert_equal nop.to_s, "nop".force_encoding("ASCII-8BIT")
    assert_not_equal nop.to_s, "nop2".force_encoding("ASCII-8BIT")
  end

  def test_assemble
    push_eax = Instr.assemble("push eax".force_encoding("ASCII-8BIT"))
    assert_equal push_eax.bin, "P".force_encoding("ASCII-8BIT")
    nop = Instr.assemble("nop".force_encoding("ASCII-8BIT"))
    assert_equal nop.bin.force_encoding("ASCII-8BIT"), "\x90".force_encoding("ASCII-8BIT")
  end

  def test_args
    pop_eax = Instr.assemble("pop eax".force_encoding("ASCII-8BIT"))
    assert_equal pop_eax.args.size, 1
    r_eax_1 = pop_eax.args.first
    r_eax_2 = Instr.str2reg("eax".force_encoding("ASCII-8BIT"))
    assert_equal r_eax_1.symbolic, r_eax_2.symbolic

    push_esp = Instr.assemble("push esp".force_encoding("ASCII-8BIT"))
    assert_equal push_esp.args.size, 1
    r_esp_1 = push_esp.args.first
    r_esp_2 = Instr.str2reg("esp".force_encoding("ASCII-8BIT"))
    assert_equal r_esp_1.symbolic, r_esp_2.symbolic
    assert_equal push_esp.dst.symbolic, r_esp_2.symbolic
    assert_nil push_esp.src

    mov_eax_ebx = Instr.assemble("mov eax, ebx".force_encoding("ASCII-8BIT"))
    assert_equal mov_eax_ebx.args.size, 2
    r_ebx = Instr.str2reg("ebx".force_encoding("ASCII-8BIT"))
    r_eax = Instr.str2reg("eax".force_encoding("ASCII-8BIT"))
    assert_equal mov_eax_ebx.src.symbolic, r_ebx.symbolic
    assert_equal mov_eax_ebx.dst.symbolic, r_eax.symbolic


  ##mov_eax_0 = Instr.assemble("mov eax, 0")

  ##assert_equal mov_eax_ebx.src, Instr.str2reg("ebx")
  ##assert_equal mov_eax_ebx.dst, Instr.str2reg("eax")
  end

end
