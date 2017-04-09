module OpenSSL
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
