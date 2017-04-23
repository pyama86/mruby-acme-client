module OpenSSL
  module X509
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
