private_key = OpenSSL::PKey::RSA.new(4096)
endpoint = "http://127.0.0.1:4000/"
client = Acme::Client.new(
  private_key,
  endpoint,
  { request: { open_timeout: 5, timeout: 5 } }
)

registration = client.register('mailto:contact@example.org')
registration.agree_terms

domains = %w(eample.org www.example.org)

domains.each do |n|
  authorization = client.authorize(n)

  challenge = authorization.http01
  challenge.put_content '/var/www/html'

  challenge = client.fetch_authorization(authorization.uri).http01
  challenge.request_verification # => true
  puts challenge.authorization.verify_status # => 'pending'

  sleep(1)
  puts challenge.authorization.verify_status # => 'valid'
end
csr = Acme::Client::CertificateRequest.new(domains)
certificate = client.new_certificate(csr)
{
  'privkey.pem' => certificate.request.private_key.to_pem,
  "cert.pem" => certificate.to_pem,
  "chain.pem" => certificate.chain_to_pem,
  "fullchain.pem" => certificate.fullchain_to_pem
}.each do |k,v|
  File.open(k, 'w'){|fp|
    fp.puts v
  }
end
