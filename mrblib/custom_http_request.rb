class CustomHttpRequest < HttpRequest
  def initialize(endpoint, crypto)
    @endpoint = endpoint
    @directory_uri = full_path("/directory")
    @crypto = crypto
    @nonces = []
  end

  def post(uri, payload)
    nonce = pop_nonce
    body = @crypto.generate_signed_jws(nonce, payload)
    response = super(full_path(uri), body)
    store_nonce(response.headers)
    response
  end

  def get(uri, payload={})
    super(full_path(uri), payload)
  end

  def head(uri)
    super(full_path(uri))
  end

  def path_strip(uri)
    uri.gsub(/^\/+|\/+$/, '')
  end

  def full_path(uri)
    (uri =~ /^http/ ? uri : "#{path_strip(@endpoint)}/#{path_strip(uri)}").gsub(%r{http://127.0.0.1/}, 'http://127.0.0.1:4000/')
  end

  def store_nonce(response_headers)
    @nonces << response_headers['replay-nonce']
  end

  def pop_nonce
    if @nonces.empty?
      get_nonce
    else
      @nonces.pop
    end
  end

  def get_nonce
    head(@directory_uri)['replay-nonce']
  end
end

class SimpleHttp::SimpleHttpResponse
  def success?
    status =~ /^2/
  end
end
