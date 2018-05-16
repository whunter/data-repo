# OSF Integration

## Create an OSF Developer Application
In order to integrate an application you must first register it with the Open Science Framework.
This can be done by creating a Developer App here: [https://osf.io/settings/applications/](https://osf.io/settings/applications/)

After your Developer App is created you will be given a Client ID and Client secret. These will need to be available to your application. In VTechData they are assigned to Rails secrets variables.
```
Rails.application.secrets.osf.client_id = <your Client ID>
Rails.application.secrets.osf.client_secret = <your Client secret>
```

## Authenticate with the OSF API
In order to make calls to the OSF API the user must first be authenticated. This is handled in the [OsfAuthController class](https://github.com/VTUL/data-repo/blob/dev/app/controllers/osf_auth_controller.rb).
OSF utilizes the Oauth2 protocol for authentication so we're using the Oauth2 gem to create a client object. With the client object we can generate an authentication url that we will redirect to in order to login.
We must provide a callback route that the user will redirected back to after successfully authenticating. The url for this route must be passed to OSF as a parameter in the authentication url.
```
  def get_client
    @client ||=  OAuth2::Client.new(
      Rails.application.secrets['osf']['client_id'],
      Rails.application.secrets['osf']['client_secret'],
      :site => Rails.application.config.osf_auth_site,
      :authorize_url=> Rails.application.config.osf_authorize_url,
      :token_url=> Rails.application.config.osf_token_url
    )
  end
```
```
  def auth_url
    @auth_url ||= @client.auth_code.authorize_url(
      :redirect_uri => callback_url,
      :scope => 'osf.full_read',
      :response_type => 'code',
      :state => 'iuasdhf734t9hiwlf7'
    )
  end
```
When the user is redirected back to the application the callback action will create a token from the code that was passed along in the redirect. This token can then be used to make calls against the OSF API. After creating the token the user will be redirected to the page that lists all of the projects that the user has created in the OSF.
```
  def callback
    code = params['code']
    if !code.blank?
      token = @client.auth_code.get_token(code, :redirect_uri => callback_url)
      if !token.blank?
        session['oauth_token'] = token.to_json
        redirect_to '/files/new#osf' 
      end
    end
  end
```

## List the user's projects
The [OsfImportTools class](https://github.com/VTUL/data-repo/blob/dev/lib/vtech_data/osf_import_tools.rb) provides methods used to make calls against the OSF API. Here it is used to query the API for a list of all of the logged in user's projects.
```
  def get_user_projects
    begin
      me_obj = osf_get_object('https://api.osf.io/v2/users/me/')
      nodes_link = me_obj['data']['relationships']['nodes']['links']['related']['href']
      nodes_obj = osf_get_object(nodes_link)
      ret_val = nodes_obj['data'].map{ | project |
        if project['attributes']['category'] == 'project'
          contributors_link = project['relationships']['contributors']['links']['related']['href']
          contributors_obj = osf_get_object(contributors_link)
          { 
            'id' => project['id'], 
            'links' => project['links'], 
            'attributes' => project['attributes'], 
            'contributors' => contributors_obj['data'].map{| contributor | {
              'name' => contributor['embeds']['users']['data']['attributes']['full_name'],
              'creator' => contributor['attributes']['index'] == 0 ? true : false
            }}
          }
        else
          nil
        end
      }
    rescue
      ret_val = { errors: true } 
    end
    return ret_val
  end
```
It uses helper methods from the same class to accomplish this.
```
  def osf_get_object url
    response = osf_get url
    begin
    ret_val = JSON.parse(response.body)
    rescue
      ret_val = {errors: true}
      Rails.logger.warn "error parsing response"
    end
    return ret_val
  end

  def osf_get url
    begin
      response = @token.get(url)
    rescue
      puts "it broke"
    end
    response rescue nil
  end
```
After building a list of all of the user's project they are then rendered in a simple [view partial](https://github.com/VTUL/data-repo/blob/dev/app/views/osf_api/list.html.erb). Each entry has links to the project in the OSF's interface as well as a link to the detail page for this project in VTechData.

## Show the details for a specific project
If the user clicks a link for the detail page of a project then the [OsfImportTools class](https://github.com/VTUL/data-repo/blob/dev/lib/vtech_data/osf_import_tools.rb) will be used to query for a specific project and build an object that will be passed on to the detail view.
```
  def get_project_details proj_url
    proj_obj = osf_get_object(proj_url)
    project = proj_obj['data']
    contributors_link = project['relationships']['contributors']['links']['related']['href']
    contributors_obj = osf_get_object(contributors_link)
    project['contributors'] = contributors_obj['data'].map{| contributor | {
        'name' => contributor['embeds']['users']['data']['attributes']['full_name'],
        'creator' => contributor['attributes']['index'] == 0 ? true : false
      }}
    return project
  end
```