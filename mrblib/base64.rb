module Base64
  def self.urlsafe_base64(data)
    encode(data).to_s.gsub(/\+/, "-").gsub(/\//, "_").sub(/[\s=]*\z/, '')
  end
end
