# frozen_string_literal: true

class Acme::Client::Resources::Challenges::HTTP01 < Acme::Client::Resources::Challenges::Base
  CHALLENGE_TYPE = 'http-01'.freeze
  CONTENT_TYPE = 'text/plain'.freeze

  def content_type
    CONTENT_TYPE
  end

  def file_content
    authorization_key
  end

  def filedir
    ".well-known/acme-challenge"
  end

  def filename
    "#{filedir}/#{token}"
  end

  def put_content(document_root)
    `mkdir -p #{File.join(document_root, filedir)}`

    File.open(File.join(document_root, filename), 'w') do |f|
      f.puts file_content
    end
  end
end
