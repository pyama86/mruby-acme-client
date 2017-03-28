class Acme::Client::Crypto
  attr_reader :private_key

  def initialize(private_key)
    @private_key = private_key
  end

  def generate_signed_jws(nonce, payload)
    header = { alg: jws_alg, jwk: jwk }
    encoded_header = Base64.urlsafe_base64(header.merge(nonce: nonce).to_json)

    encoded_payload = Base64.urlsafe_base64(payload.to_json)
    signature_data = "#{encoded_header}.#{encoded_payload}"
    signature = private_key.sign digest, signature_data
    encoded_signature = Base64.urlsafe_base64(signature)
    {
      header: header,
      protected: encoded_header,
      payload: encoded_payload,
      signature: encoded_signature
    }.to_json
  end

  def thumbprint
    Base64.urlsafe_base64 digest.digest(jwk.to_json)
  end

  def digest
    # TODO: Binding
    OpenSSL::Digest::SHA256.new
  end

  private

  def jws_alg
    { 'RSA' => 'RS256', 'EC' => 'ES256' }.fetch(jwk[:kty])
  end

  def jwk
    @jwk ||= case private_key
             when OpenSSL::PKey::RSA
               rsa_jwk
             else
               raise ArgumentError, "Can't handle #{private_key} as private key, only OpenSSL::PKey::RSA"
    end
  end

  def rsa_jwk
    {
      e: Base64.urlsafe_base64(public_key.e.to_s(2)),
      kty: 'RSA',
      n: Base64.urlsafe_base64(public_key.n.to_s(2))
    }
  end

  def public_key
    @public_key ||= private_key.public_key
  end
end
