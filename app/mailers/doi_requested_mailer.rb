class DoiRequestedMailer < ApplicationMailer
  default from: Sufia.config.from_email

  def notification_email(doi_request)
    doi_request = DoiRequest.find(doi_request.id)
    @asset = Collection.find(doi_request.asset_id)
    if @asset
      mail(to: 'vtechdata@vt.edu', subject: 'New DOI request')
    else
      Rails.logger.error "Can not find doi request to send notification"
    end
  end
end
