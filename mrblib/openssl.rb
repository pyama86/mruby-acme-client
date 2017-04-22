module OpenSSL
 # class PKey
 #   class RSA
 #     def initialize(length)
 #       @_private_key = `openssl genrsa #{length} 2> /dev/null`.chomp
 #       th = Tempfile.new 'private_key'

 #       File.open(th.path, 'w'){|fp|
 #         fp.puts @_private_key
 #       }
 #       @_public_key = `openssl rsa -in #{th.path} -pubout 2> /dev/null`.chomp
 #       th.close
 #     end

 #     def public_key
 #       self.clone
 #     end

 #     def to_s
 #       @_private_key
 #     end

 #     def to_pem
 #       @_private_key
 #     end

 #     def e
 #       th = Tempfile.new 'private_key'
 #       File.open(th.path, 'w'){|fp|
 #         fp.puts @_private_key
 #       }
 #       th.close false
 #       OpenSSL::BN.new `printf '%x' "$(openssl rsa -in "#{th.path}" -noout -text | awk '/publicExponent/ {print $2}')"`.chomp
 #     end

 #     def n
 #       th = Tempfile.new 'private_key'
 #       File.open(th.path, 'w'){|fp|
 #         fp.puts @_private_key
 #       }
 #       th.close false
 #       OpenSSL::BN.new `openssl rsa -in "#{th.path}" -noout -modulus | cut -d'=' -f2`
 #     end

 #     def sign(digest, signature_data)
 #       th = Tempfile.new 'private_key'
 #       File.open(th.path, 'w'){|fp|
 #         fp.puts @_private_key
 #       }
 #       th.close false
 #       `printf '%s' "#{signature_data}" | openssl dgst -sha256 -sign "#{th.path}"`.chomp
 #     end
 #   end
 # end

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
