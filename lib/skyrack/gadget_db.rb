require 'skyrack/gadget_tree'
require 'skyrack/instr'
require 'skyrack/payload'
require 'sqlite3'

class GadgetDbException < Exception; end

class GadgetDb

  DB_SCHEMA = File.expand_path(File.join(__FILE__, '..', '..', '..', 'gadgets.sql'))

  def infos
    @infos ||= sql("SELECT * FROM dll_info").first
  end

  def file
    @exe_filename ||= File.join(infos['path'], infos['name'])
  end

  def regs
    cpu.class::Reg.s_to_i.keys
  end

  def reg_from_str(str)
    cpu.class::Reg.from_str(str)
  end

  def cpu
    c = Metasm.const_get infos['cpu']
    @cpu ||= c.new
  end

  def create_schema(filename, exe)
    puts "creating schema %s" % DB_SCHEMA if @verbosity > 0
    schema = File.read(DB_SCHEMA).split(';').each do |create|
      next if create.strip.empty?
      @db.execute(create + ';')
    end

    return unless filename
    name = File.basename filename
    path = File.dirname filename
    require 'openssl'
    full = File.join(path, name)
    md5    = Digest::MD5.hexdigest(   File.read(full))
    sha512 = Digest::SHA512.hexdigest(File.read(full))
    req = "INSERT INTO dll_info (name, path, md5, sha512, size, cpu)" +
        " VALUES ('%s', '%s', '%s', '%s', %d, '%s')" %
    [self.quote(name), self.quote(path), self.quote(md5), self.quote(sha512),
        File.new(full, 'r').stat.size, self.quote(exe.cpu.class.to_s.split('::').last)]
    @db.execute(req)
  end

  def get_default_name
    name = Dir[File.join('.', 'db', '*.sqlite3'), File.join('*sqlite3')].first
    raise GadgetDbException.new("No database found (try option -f)") unless name
    $stderr.puts "using database %s" % name
    name
  end

  def initialize(dbname = nil, exe = nil)
    if exe.nil?
      # open an existing database
      dbname = get_default_name() if dbname.nil?
      common_initialize(dbname)
    else
      # create a new database
      raise GadgetDbException.new("file %s already exists" % dbname) if File.exists? dbname
      common_initialize(dbname)
      create_schema(dbname, exe)

      # prevents sqlite from flushing and then increases speed for writing
      # http://www.sqlite.org/pragma.html#pragma_synchronous
      sql("PRAGMA synchronous = 0")

      # ensures db is flushed when terminating
      trap('INT') {
        if @in_sql
          puts "actually performing SQL query, cannot close"
        else
          trap('INT', 'DEFAULT')
          puts '', 'aborting : flushing db'
          close
        end
      }
    end
    Instr.cpu = cpu
  end

  def common_initialize(dbname)
    @db = SQLite3::Database.new(dbname)
    @verbosity = $verbosity || 0
    @in_sql = false
    @db.results_as_hash = true
  end

  def search_gadget(search)
    search_by_gadget(search) do |gadget|
      satisfied = true
      sp = search[:post]
      satisfied &= gadget.preserve_target? if satisfied && sp[:preserve_target]
      satisfied &= gadget.preserve_eip? if satisfied && sp[:preserve_eip]
      satisfied &= gadget.preserve_regs(sp[:preserve]) if satisfied && sp[:preserve]
      sub_satisfied = false
      if satisfied && search[:any].size > 0
        search[:any].each do |instr_ary|
          sub_satisfied |= gadget.include_str_ary?(instr_ary)
        end
      end
      satisfied &= sub_satisfied

      yield(gadget) if satisfied
      satisfied
    end
  end

  def save_function(addrs, opts)
    num = 0
    addrs.each do |addr|
      save_interesting_addr(addr, opts, num)
      num += 1
    end
  end

  def save_interesting_addr(addr, opts, num = 0)
    vals = [addr, quote(opts[:desc]), quote(opts[:dest]), opts[:value], num]
    query = "INSERT INTO builder (address, description, dst, value, num)" +
      " VALUES (%d, '%s', '%s', '%s', %d)" % vals
    sql(query)
  end

  # @TODO: FIXME advanced search
  def find_interesting(opts)
    query = "SELECT * FROM builder"
    sql(query).each do |res|
      addr     = res['address']
      ret_addr = res['ret_addr']
      g = gadget_build(addr, ret_addr)
      unless g
        puts "no gadget found @0x%08x" % addr
        next
      end
      yield( g.from_addr(addr) )
    end
  end

  def save_gadget(gadget)
    return if gadget.size <= 0
    sql("BEGIN");
    gadget.each_vertex do |instr|
      ret_addr = gadget.ret_addr
      if ret_addr == instr.addr then
        ret_distance = 0
      else
        ret_distance = gadget.from_addr(instr.addr).size
      end
      query = "INSERT INTO gadgets (address, opcode, arg1, " +
        "arg2, bin, ret_addr, ret_distance) VALUES "
      query << save_instr_values(instr, ret_addr, ret_distance)
      sql(query)
    end
    #puts gadget.write_to_graphic_file('png', 'blah_%d.jpg' % gadget.ret_addr)
    sql("COMMIT");
  end

  def save_expr(gadget)
    # @TODO ?
  end

  def save_instr_values(instr, ret_addr, ret_distance)
    "(%d, '%s', '%s', '%s', '%s', %d, %d)" %
    [
      instr.addr, quote(instr.to_s),
      quote(instr.dst),
      quote(instr.src),
      instr.bin.unpack('H*').first,
      ret_addr,
      ret_distance
    ]
  end

  def sql(sql_str)
    @in_sql = true
    res = nil
    begin
      puts "executing '%s'" % sql_str if @verbosity > 1
      res = @db.execute(sql_str)
    rescue SQLite3::ConstraintException => e
      if e.message == "column address is not unique"
        puts "addr alread stored" if @verbosity > 3
      else
        puts "error for #{sql_str}" if @verbosity > 2
      end
    end
    @in_sql = false
    res
  end

  # yields all instruction gadgets matching conditions in search.
  # conditions may include:
  # :any
  # :address
  # :dst
  # :src
  # :limit
  def search_by_gadget(search)
    conds = []
    limit = 10
    search.each do |k, v|
      case k
      when :any
        v.each do |ary|
          conds << "((%s) AND ret_distance > %d)" % [cond_any(ary).join(' OR '), ary.size]
        end
      when :address
        conds += cond_by_addr(v) unless v.size == 0
      when :dst
        conds << cond_by_dst(v)  unless v.size == 0
      when :src
        conds << cond_by_src(v)  unless v.size == 0
      when :limit
        limit = v
      end
    end
    return if conds.size == 0
    found = []
    search(conds).each do |row|
      addr     = row['address']
      ret_addr = row['ret_addr']
      g = gadget_build(addr, ret_addr)

      next unless g
      next if found.include?(g)

      if yield(g)
        found << g
        limit -= 1
      end

      break if limit == 0
    end
  end

  def cond_any(v)
    v.inject([]) { |a, src| a << "opcode LIKE '%%%s%%'" % quote(src) }
  end

  def cond_by_addr(addr, limit)
    ["address = %d" % addr]
  end

  def cond_by_src(v)
    "(%s)" % v.inject([]) { |a, src| a << "arg2 = '%s'" % quote(src) }.join(' OR ')
  end

  def cond_by_dst(v)
    "(%s)" % v.inject([]) { |a, dst| a << "arg1 = '%s'" % quote(dst) }.join(' OR ')
  end

  def reg_with_shared_bits(reg)
    reg_c = reg_from_str(reg)
    cpu.class::Reg.s_to_i.keys.select { |k| reg_from_str(k).share? reg_c }
  end

  def search_by_ret_addr(addr, limit)
    search(["ret_addr = %d" % addr])
  end

  def search(conds)
    req = "SELECT * FROM gadgets WHERE "
    req << conds.join(' AND ')
    req << " ORDER BY ret_distance ASC"
    puts req if @verbosity > 2

    if @verbosity > 3 then
      req_count = "SELECT COUNT(*) FROM gadgets WHERE " << conds.join(' AND ')
      res_count = sql(req_count).first
      puts "found %d" % [res_count[0].to_i]
    end

    res = sql(req)

    if block_given?
      res.each do |row|
        yield(row)
      end
    else
      res
    end
  end

  def close
    @db.close
  end

  def get_ret_addr(addr)
    req = "SELECT ret_addr FROM gadgets WHERE address = %d" % addr
    res = sql(req)
    res.size == 0 ? nil : res.first["ret_addr"].to_i
  end

  def gadget_build(addr, ret_addr = nil)
    ret_addr ||= get_ret_addr(addr)
    gadget = Gadget.new
    instrs = search_by_ret_addr(ret_addr, -1).select {|r| r['address'] >= addr}
    instrs = instrs.map { |r| Instr.from_db_row r }.sort
    gadget << instrs.first
    instrs.map do |instr|
      gadget << instr if instr.addr == gadget.last.next_instr_addr
    end
    gadget
  end

  # returns an array of Gadget
  def get_function(type, value, dst = '%')
    query = "SELECT * FROM builder WHERE description = '%s' " +
      "AND value = %d AND dst LIKE '%s' ORDER BY num" %
      [quote(type), value.to_i, quote(dst)]
    res = sql(query).inject(Payload.new) {|a, e| a << gadget_build(e['address'])}
    raise "no function %s, %s found for %s" % [type, value, dst] if res.size == 0
    res
  end

  def get_address(type)
    query = "SELECT * FROM builder WHERE description = '%s'" % quote(type)
    sql(query).first['address']
  end

  def delete_interesting(addr)
    query =	"DELETE FROM builder WHERE address = %d" % addr
    sql(query)
  end

  # returns the address of an equivalent gadget found in the db, or nil
  def find_equivalent(gadget)
    search_by_gadget( {:any => [gadget.first.to_s], :dst => [gadget.size]} ) 	{ |found_gadget|
      return found_gadget if gadget == found_gadget
    }
    nil
  end

  def find_equivalent_expr(expr)
    require 'skyrack/expr'
    puts "trying to match %s" % expr
    sql("SELECT * FROM gadgets WHERE ret_addr != address").each do |row|
      g = gadget_build(row['address'])
      begin
        res = g.expr.select {|k,v| v == expr.sky_reduce }
        puts "found %s" % res.inspect if res.size > 0
        yield(g) if res.size > 0
      rescue RuntimeError
        # @TODO: make this rescue more specific than RuntimeError
      end
    end
  end

  def quote(str)
    return "" unless str
    str = str.to_s
    SQLite3::Database::quote(str)
  end

end

