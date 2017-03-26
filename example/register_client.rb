private_key = OpenSSL::PKey::RSA.new(4096)

endpoint = 'http://127.0.0.1:4000/'
client = Acme::Client.new(
  private_key,
  endpoint,
  endpoint+"directory",
  { request: { open_timeout: 5, timeout: 5 } }
)

registration = client.register('mailto:contact@example.com')

# You may need to agree to the terms of service (that's up the to the server to require it or not but boulder does by default)
registration.agree_terms
