module OpenSSL
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

      def to_s
        @_private_key
      end

      def to_pem
        @_private_key
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
        `printf '%s' "#{signature_data}" | openssl dgst -sha256 -sign "#{th.path}"`.chomp
      end
    end
  end

  module X509
    class Request
      attr_reader :private_key
      def initialize(common_name, names, private_key)
        @private_key = private_key
        th = Tempfile.new 'openssl'
        File.open(th.path, 'w'){|fp|
          fp.puts `cat #{`openssl version -d`.split[1].gsub(/"/, '')}/openssl.cnf`.chomp
          fp.puts "[SAN]"
          fp.puts "subjectAltName=#{names.map { |name| "DNS:#{name}" }.join(', ')}"
        }
        ph = Tempfile.new 'private_key'
        File.open(ph.path, 'w'){|fp|
          fp.puts private_key.to_s
        }
        @csr = `openssl req -new -sha256 -key #{ph.path}  -subj "/CN=#{common_name}/" -reqexts SAN -config "#{th.path}"`.chomp
      end

      def to_der
        th = Tempfile.new 'csr'
        File.open(th.path, 'w'){|fp|
          fp.puts @csr
        }
        `openssl req -in "#{th.path}" -inform PEM -outform DER`.chomp
      end

      def to_pem
        th = Tempfile.new 'csr'
        File.open(th.path, 'w'){|fp|
          fp.puts @csr
        }
        `openssl req -in "#{th.path}" -outform PEM`.chomp
      end

      def to_pem
        th = Tempfile.new 'csr'
        File.open(th.path, 'w'){|fp|
          fp.puts @csr
        }
        `openssl req -in "#{th.path}" -inform PEM -outform PEM`.chomp
      end
    end

    class Certificate
      def initialize(body)
        @body = body
      end

      def to_pem
        th = Tempfile.new 'csr'
        File.open(th.path, 'w'){|fp|
          fp.puts @body
        }
        `openssl x509 -in #{th.path} -text -noout -inform der`
      end
    end
  end
end
