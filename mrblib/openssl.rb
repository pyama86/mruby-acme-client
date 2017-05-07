module OpenSSL
  class ASN1Data
    attr_accessor :value, :tag, :tag_class, :infinite_length
  end

  class Primitive < ASN1Data
    attr_accessor :tagging
  end

  class Constructive < ASN1Data
    attr_accessor :tagging
  end

  class Config
    include Enumerable
    def to_s
      ary = []
      @data.keys.sort.each do |section|
        ary << "[ #{section} ]\n"
        @data[section].keys.each do |key|
          ary << "#{key}=#{@data[section][key]}\n"
        end
        ary << "\n"
      end
      ary.join
    end
  end

  module X509
    class ExtensionFactory
      def create_extension(*arg)
        if arg.size > 1
          create_ext(*arg)
        else
          send("create_ext_from_"+arg[0].class.name.downcase, arg[0])
        end
      end

      def create_ext_from_array(ary)
        raise ExtensionError, "unexpected array form" if ary.size > 3
        create_ext(ary[0], ary[1], ary[2])
      end

      def create_ext_from_string(str) # "oid = critical, value"
        oid, value = str.split(/=/, 2)
        oid.strip!
        value.strip!
        create_ext(oid, value)
      end

      def create_ext_from_hash(hash)
        create_ext(hash["oid"], hash["value"], hash["critical"])
      end
    end

    class Extension
      def to_s # "oid = critical, value"
        str = self.oid
        str << " = "
        str << "critical, " if self.critical?
        str << self.value.gsub(/\n/, ", ")
      end

      def to_h # {"oid"=>sn|ln, "value"=>value, "critical"=>true|false}
        {"oid"=>self.oid,"value"=>self.value,"critical"=>self.critical?}
      end

      def to_a
        [ self.oid, self.value, self.critical? ]
      end
    end
  end
end
