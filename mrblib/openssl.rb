def sed
  `uname`.chomp  =~ /Linux/ ?  'sed -r' : 'sed -E'
end

SHELLESCAPE_REGEXP = /([^A-Za-z0-9_\-.,:\/@\n])/
NEWLINE_REGEXP     = /\n/

def shellescape(str)
  str = str.to_s
  return "''".dup if str.empty?

  str = str.dup
  str.gsub!(SHELLESCAPE_REGEXP, "\\\\\\1")
  str.gsub!(NEWLINE_REGEXP, "'\n'")
  str
end

module OpenSSL
  module Digest
    class SHA256
      def digest(token)
        `printf '%s' '#{token}' | openssl dgst -sha256  -binary`.chomp
      end
    end
  end

  class BN
    def initialize(v)
      @_v = v
    end

    def to_s(base=2)
      [@_v.gsub(/\s/, '').gsub(/^(.(.{2})*)$/, "0\\1")].pack "H*"
    end
  end

  module PKey
    class RSA
      def initialize(length)
        @_private_key = `openssl genrsa #{length} 2> /dev/null`.chomp
        th = Tempfile.new 'private_key'

        File.open(th.path, 'w'){|fp|
          fp.puts @_private_key
        }
        @_public_key = `openssl rsa -in #{th.path} -pubout 2> /dev/null`.chomp
        th.close
      end

      def public_key
        self.clone
      end

      def e
        th = Tempfile.new 'private_key'
        File.open(th.path, 'w'){|fp|
          fp.puts @_private_key
        }
        th.close false
        OpenSSL::BN.new `printf '%x' "$(openssl rsa -in "#{th.path}" -noout -text | awk '/publicExponent/ {print $2}')"`.chomp
      end

      def n
        th = Tempfile.new 'private_key'
        File.open(th.path, 'w'){|fp|
          fp.puts @_private_key
        }
        th.close false
        OpenSSL::BN.new `openssl rsa -in "#{th.path}" -noout -modulus | cut -d'=' -f2`
      end

      def sign(digest, signature_data)
        th = Tempfile.new 'private_key'
        File.open(th.path, 'w'){|fp|
          fp.puts @_private_key
        }
        th.close false
        `printf '%s' "#{shellescape(signature_data.gsub(/\000/, ''))}" | openssl dgst -sha256 -sign "#{th.path}"`.chomp
      end
    end
  end

  module X509
    class Request
      def csr
        @csr ||= Csr
      end

      def initialize
        yield csr
      end
    end

    class Csr
      attr_accessor :public_key, :subject, :version
      def sign
        `openssl req -new -key server.key -out server.csr -sha256`.chomp
      end
    end
  end
end
