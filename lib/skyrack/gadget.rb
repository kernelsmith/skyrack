require 'skyrack/instr'

class Gadget < Array
  attr_accessor :base_addr, :dis, :expr

  def initialize(*args)
    if args.size > 0 && args.first.is_a?(String)
      str_dis = Gadget.dis_from_str(args.first)
      res = super(str_dis.decoded.values)
      res.dis = str_dis
      res
    else
      super(*args)
    end
  end

  # to build with strings such as "mov eax, 1; nop; ret"
  def self.from_str(str)
    Gadget.new( str.split(';').inject([]) { |a, instr| a << Instr.as(instr) } )
  end

  def expr
    @expr ||= Instr.cpu.code_binding(dis, 0)
  end

  def dis=(v)
    @dis = v
  end

  def dis(base_addr=0, eip=base_addr)
    if @dis
      @dis
    else
      eip = 0
      str = inject("") 	{ |str, instr| str << instr.bin }
      @dis = Gadget.dis_from_str(str, base_addr, eip)
    end
  end

  def	self.dis_from_str(raw, base_addr=0, eip=base_addr)
    sc = Metasm::Shellcode.decode(raw, Instr.cpu)
    sc.base_addr = base_addr
    # @TODO: FIXME sc.disassemble_fast(eip)
    sc.disassemble(eip)
  end

  # an instruction gadget can be found equal to an other one only and only if
  # the sequence of the instructions is the same
  include Comparable

  def <=>(gadget)
    return (size <=> gadget.size) unless size == gadget.size
    ret = 0
    same_gadgets = true
    for i in 0...size
      same_gadgets &= (self[i].bin == gadget[i].bin)
      unless same_gadgets
        ret = 1
        break
      end
    end
    ret
  end

  # returns true if gadget matches instr_ary (non contiguously), e.g.:
  # [pop r8; inc rax; pop r9] will match instr_ary ['pop r8', 'pop r9']
  def include_str_ary?(instr_ary)
    last_match = 0
    found = 0
    instr_ary.each do |instr|
      self[last_match..-1].each_with_index do |g_ins, idx|
        if g_ins.to_s.index instr
          found += 1
          last_match += idx + 1
          break
        end
      end
    end
    found == instr_ary.size
  end

  def base_addr
    @base_addr ||= self.first.addr
  end

  def modify_regs(reg_gadget)
    reg_gadget.inject(false) 	{ |b, reg| b |= modify_reg(reg) }
  end

  def preserve_regs(reg_gadget)
     !modify_regs(reg_gadget)
  end

  def modify_reg(reg, idx = 0)
    self[idx..-1].inject(false) { |s, i| s |= i.modify_reg(reg) }
  end

  def preserve_target?
    target = first.dst
    !modify_reg(target, 1)
  end

  def preserve_eip?
    !self[1..-2].inject(false) { |s, i| op = i.instr.opcode.props;  s |= (op[:setip] || op[:stopexec]) }
  end

  def to_s
    res = ["====== 0x%x ======" % base_addr]
    each do |i|
      res << "%s" % i.to_s(true)
    end
    res.join("\n")
  end

  # returns true only if the argument is included in the current gadget
  # (no order)
  def include_gadget?(gadget)
    if self.size < gadget.size
      false
    else
      inject(true) { |b, element| b &= gadget.include? element }
    end
  end

  # returns true only if the argument is a subset of the current gadget
  # (same order)
  def include_gadget?(gadget)
    if self.size < gadget.size
      false
    else
      res = true
      each_with_index do |idx, e|
        res &= (gadget[idx] == e)
      end
    end
  end

  def get_binding
    cpu = first.cpu
    binding = nil
    self.each do |instr|
      binding = cpu.get_backtrace_binding(instr)
    end
  end

end
