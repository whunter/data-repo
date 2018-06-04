# OSF Integration

## Overview

The University Libraries at Virginia Tech is continually attempting to explore new use cases for the VTechData repository, brainstorm ways to encourage more submissions, and find connections and integrations to make the repository more useful.  Throughout these efforts we have realized that the ability to pass objects from the Open Science Framework (OSF) into the VTechData repository would provide a very large benefit to researchers in the community, allowing them to work collaboratively within the OSF and take advantage of the publishing and curation services offered through the Libraries. 

The code in this repository connects the Open Science Framework to the Samvera application, allowing users to import projects and other components into Samvera. While a minimal set of metadata from the OSF is transferred into Samvera metadata fields, the bulk of the OSF project or component is imported as a ZIP.

We project that this new service integration will allow researchers to more easily benefit from both the OSF and the data repository at Virginia Tech, and through similar connections with other data repositories running on Samvera.

This software is licensed under the Virginia Tech Non-Commerical Purpose license[https://github.com/VTUL/data-repo/blob/dev/SamveraOSF_VT_Noncommercial_Purpose_License.pdf]. Permission to use, copy, modify, and distribute this compilation for Non-Commercial Purpose is hereby granted without fee, subject to terms of this license.

## Implementation Notes:

### Create an OSF Developer Application
In order to integrate an application you must first register it with the Open Science Framework.
This can be done by creating a Developer App here: [https://osf.io/settings/applications/](https://osf.io/settings/applications/)

After your Developer App is created you will be given a Client ID and Client secret. These will need to be available to your application. In VTechData they are assigned to Rails secrets variables.
```
# In config/secrets.yml

# OSF client settings
osf:
  client_id: <your client id>
  client_secret: <your client secret>
```


### Authenticate with the OSF API
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


### List the user's projects
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


### Show the details for a specific project
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

Once this object is created it will be passed along to the [detail view](https://github.com/VTUL/data-repo/blob/dev/app/views/osf_api/detail.html.erb) for rendering.


### Import OSF Project into VTechData

When on the project detail page users will have the option to import their project into VTechData. This is again handled by the [OsfImportTools class](https://github.com/VTUL/data-repo/blob/dev/lib/vtech_data/osf_import_tools.rb) via the [import_project](https://github.com/VTUL/data-repo/blob/dev/lib/vtech_data/osf_import_tools.rb#L38-L101) method which recursively visits all of the nodes contained in the project with the [walk_nodes](https://github.com/VTUL/data-repo/blob/dev/lib/vtech_data/osf_import_tools.rb#L103-L125) method.

This process takes some time so it is run in a background job
```
  # in app/controllers/osf_api_controller.rb

  def import
   Sufia.queue.push(OsfImportJob.new(@oauth_token, params["project_id"], current_user))
   redirect_to '/dashboard', notice: 'Your project is currently being imported. You should receive an email when the process has completed.'
  end
```

```
  # in app/jobs/osf_import_job.rb
  
  def run
    osf_import_tools = OsfImportTools.new(oauth_token, current_user)
    osf_import_tools.import_project project_id
  end
```

As each node is visited, metadata is recorded and associated files are downloaded and used to construct a zip file. 

A GenericFile object is [created](https://github.com/VTUL/data-repo/blob/dev/lib/vtech_data/osf_import_tools.rb#L63-L74) based on the OSF project metadata and is put into Fedora.

The zip file is then attached to the GenericFile record in Fedora.
```
  ingest_job = IngestLocalFileJob.new(item.id, tmp_path, project_name + '.zip', @current_user.user_key)
  ingest_job.run
```

A Collection object is then [created](https://github.com/VTUL/data-repo/blob/dev/lib/vtech_data/osf_import_tools.rb#L81-L93) with OSF metadata and the GenericFile object is added as a member. This object is then also saved into Fedora.

Finally, since this process is being run in a background job, an email is sent to the logged in user to inform them that the process has completed, either successfully or with errors.
```
  if(!item.id.nil? && !collection.id.nil?)
    success = true      
  else
    success = false
  end
  OsfNotificationMailer.notification_email(success, collection.id, @current_user).deliver_later
```

