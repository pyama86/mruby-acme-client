private_key = OpenSSL::PKey::RSA.new(4096)
endpoint = "http://127.0.0.1:4000/"
client = Acme::Client.new(
  private_key,
  endpoint,
  endpoint+"directory",
  { request: { open_timeout: 5, timeout: 5 } }
)

registration = client.register('mailto:contact@example.org')
registration.agree_terms


authorization = client.authorize('example.org')

puts authorization.status # => 'pending'
authorization.uri

challenge = authorization.http01

challenge.token # => "some_token"

challenge.filename # => ".well-known/acme-challenge/:some_token"

challenge.file_content # => 'string token and JWK thumbprint'

challenge.content_type
`mkdir -p #{File.join( '/Users/pyama/example.org', challenge.filedir)}`

File.open(File.join( '/Users/pyama/example.org', challenge.filename), 'w') do |f|
  f.puts challenge.file_content
end

challenge = client.fetch_authorization(authorization.uri).http01
challenge.request_verification # => true
puts challenge.authorization.verify_status # => 'pending'

sleep(5)

puts challenge.authorization.verify_status # => 'valid'
challenge.error # => nil

authorization.verify_status # => 'invalid'
authorization.http01.error # => {"type" => "...", "detail" => "..."}k
