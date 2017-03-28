module Acme; end
class  Acme::Client; end
module Acme::Client::Resources; end
module Acme::Client::Resources::Challenges; end
class  Acme::Client::Resources::Challenges::Base; end
class  Acme::Client::Resources::Challenges::DNS01 < Acme::Client::Resources::Challenges::Base; end
class  Acme::Client::Resources::Challenges::HTTP01 < Acme::Client::Resources::Challenges::Base; end
class  Acme::Client::Resources::Challenges::TLSSNI01 < Acme::Client::Resources::Challenges::Base; end
module OpenSSL; end
module OpenSSL::PKey; end
class  OpenSSL::PKey::EC; end
module OpenSSL::Digest; end
class  OpenSSL::Digest::SHA256; end

class Acme::Client
  DEFAULT_ENDPOINT = 'http://127.0.0.1:4000/'.freeze
  def initialize(private_key, endpoint=DEFAULT_ENDPOINT, connection_options={})
    @endpoint, @private_key, @connection_options = endpoint, private_key, connection_options
    @nonces ||= []
    load_directory!
  end

  attr_reader :private_key, :nonces, :endpoint, :operation_endpoints

  def crypto
    @_crypto ||= Acme::Client::Crypto.new(private_key)
  end

  def register(contact)
    payload = {
      resource: 'new-reg',
      contact: Array(contact),
    }

    response = connection.post(@operation_endpoints.fetch('new-reg'), payload)
    ::Acme::Client::Resources::Registration.new(self, response)
  end

  def authorize(domain)
    payload = {
      resource: 'new-authz',
      identifier: {
        type: 'dns',
        value: domain
      }
    }

    response = connection.post(@operation_endpoints.fetch('new-authz'), payload)
    ::Acme::Client::Resources::Authorization.new(self, response.headers['location'], response)
  end

  def fetch_authorization(uri)
    response = connection.get(uri)
    ::Acme::Client::Resources::Authorization.new(self, uri, response)
  end

  def new_certificate(csr)
    payload = {
      resource: 'new-cert',
      csr: Base64.urlsafe_base64(csr.to_der)
    }
    response = connection.post(@operation_endpoints.fetch('new-cert'), payload)

    File.open('test.pem', 'w'){|fp|
      fp.puts response.body
    }

    ::Acme::Client::Certificate.new(OpenSSL::X509::Certificate.new(response.body), response.headers['location'], fetch_chain(response), csr)
  end

  def revoke_certificate(certificate)
    payload = { resource: 'revoke-cert', certificate: Base64.urlsafe_encode64(certificate.to_der) }
    endpoint = @operation_endpoints.fetch('revoke-cert')
    response = connection.post(endpoint, payload)
    response.success?
  end

  def self.revoke_certificate(certificate, *arguments)
    client = new(*arguments)
    client.revoke_certificate(certificate)
  end

  def connection
    @connection ||= CustomHttpRequest.new(@endpoint, self.crypto)
  end

  private

  def fetch_chain(response, limit = 10)
    links = response.headers['link']
    if limit.zero? || links.nil? || links['up'].nil?
      []
    else
      issuer = connection.get(links['up'])
      [OpenSSL::X509::Certificate.new(issuer.body), *fetch_chain(issuer, limit - 1)]
    end
  end

  def load_directory!
    response = connection.directory
    body = JSON.parse(response.body)
    @operation_endpoints = {
      'new-reg' => body['new-reg'],
      'new-authz' => body['new-authz'],
      'new-cert' =>  body['new-cert'],
      'revoke-cert' =>body['revoke-cert']
    }
  rescue
    @operation_endpoints = {
      'new-authz' => "/acme/new-authz",
      'new-cert' => "/acme/new-cert",
      'new-reg' => "/acme/new-reg",
      'revoke-cert' => "/acme/revoke-cert"
    }
  end
end
