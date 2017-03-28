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
    on_complete response
  end

  def get(uri, payload={})
    on_complete super(full_path(uri), payload)
  end

  def head(uri)
    on_complete super(full_path(uri))
  end

  def path_strip(uri)
    uri.gsub(/^\/+|\/+$/, '')
  end

  def full_path(uri)
    (uri =~ /^http/ ? uri : "#{path_strip(@endpoint)}/#{path_strip(uri)}").gsub(%r{http://127.0.0.1/}, 'http://127.0.0.1:4000/')
  end

  def directory
    get(@directory_uri)
  end

  private
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

  def on_complete(response)
    error = Error.from_response(response)
    raise error if error
    response.headers['link'] = decode_link_headers(response.headers) if response.headers.key?('link')
    response
  end

  LINK_MATCH = /<(.*?)>;rel="([\w-]+)"/
  def decode_link_headers(headers)
    link_header = headers['link'].is_a?(Array) ? headers['link'] : [headers['link'] ]
    links = link_header.map { |entry|
      _, link, name = *entry.match(LINK_MATCH)
      [name, link]
    }

    Hash[*links.flatten]
  end

  class Error < ::StandardError
    attr_reader :response
    def self.from_response(response)
      status = response.status.to_i
      klass = case status
              when 400      then BadRequest
              when 400..499 then ClientError
              when 500      then InternalServerError
              when 500..599 then ServerError
              end

      raise klass.new(response) if klass
    end

    def initialize(response)
      @response = response
      super(build_error_message)
    end

    private

    def build_error_message
      return nil if @response.nil?
      message = "#{@response.body} #{@response.status}"
      message << " - #{response_error}>" if response_error
      message
    end

    def response_error
      data = @response.body
      data.error if data.respond_to?(:error) && data.error
    end
  end

  class ClientError < Error;end
  class BadRequest < ClientError;end
  class ServerError < Error;end
  class InternalServerError < ServerError;end
end

class SimpleHttp::SimpleHttpResponse
  def success?
    status =~ /^2/
  end
end
