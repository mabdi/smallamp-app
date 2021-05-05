require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements

set :port, 3000
set :bind, '0.0.0.0'

set :show_exceptions, false



class GHAapp < Sinatra::Application

  # Expects that the private key in PEM format. Converts the newlines
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # Your registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end


  # Before each request to the `/event_handler` route
  before '/event_handler' do
    get_payload_request(request)
    verify_webhook_signature
    authenticate_app
    # Authenticate the app installation in order to run API operations
    authenticate_installation(@payload)
  end


  post '/event_handler' do
#    logger.debug request
#    logger.debug @payload
    case request.env['HTTP_X_GITHUB_EVENT']
    when 'installation_repositories'
      if @payload['action'] === 'added'
        handle_repo_install(@payload['repositories_added'])
      end
    when 'workflow_run'
     if @payload['action'] === 'completed'
       handle_action_completed(@payload)
     end
    when 'installation'
      if @payload['action'] === 'created'
        handle_repo_install(@payload['repositories'])
      end
    end

    200 # success status
  end

#  error do
#     'Error: - ' + env['sinatra.error'].message
     #require 'pry' ; binding.pry
#  end

  helpers do
=begin

    def handle_action_completed(payload)
        logger.debug payload
    end

    def handle_repo_install(repo_list)
          logger.debug 'handle_repo_install'
          handle_repo_install_repo(repo_list[0])
    end

    def handle_repo_install_repo(rp)
       logger.debug rp
       r = @installation_client.repo(rp['full_name'])
       begin
          @installation_client.contents( rp['full_name'], :path => '.github/workflows/SmallAmpCIX.yml')
          logger.debug 'CI file exists, skip'
          return
       rescue Octokit::NotFound
          logger.debug 'not found, lets add it'
          my_content = File.read('SmallAmpCI.yml')
          @installation_client.create_contents(rp['full_name'],
                 '.github/workflows/SmallAmpCIX.yml',
                 "[SmallAmpApp] push SmallAmpCI.yml",
                 my_content,
                 :branch => r.default_branch)
       end
#       r = client.repo( repo )
 #      ref = 'heads/%s' % r.default_branch
  #     sha_latest_commit = client.refs(repo, ref).object.sha
   #    logger.debug 'sha_latest_commit '  + sha_latest_commit
    #   sha_base_tree = github.commit(repo, sha_latest_commit).commit.tree.sha
#       logger.debug 'sha_base_tree ' + sha_base_tree
 #      file_name = File.join(".github", "workflows", "SmallAmpCIX.yml")
  #     logger.debug 'file_name '+ file_name
   #    blob_sha = github.create_blob(repo, Base64.encode64(my_content), "base64")
    #   sha_new_tree = github.create_tree(repo, 
     #                              [ { :path => file_name, 
      #                                 :mode => "100644", 
       #                                :type => "blob", 
        #                               :sha => blob_sha } ], 
         #                          {:base_tree => sha_base_tree }).sha
 #      logger.debug 'tree created'
  #     commit_message = "[SmallAmpApp] push SmallAmpCI.yml"
   #    sha_new_commit = github.create_commit(repo, commit_message, sha_new_tree, sha_latest_commit).sha
    #   logger.debug 'sha_new_commit '+ sha_new_commit
     #  updated_ref = github.update_ref(repo, ref, sha_new_commit;)
      # logger.debug 'updated_ref ' + updated_ref
    end
=end


    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue => e
        fail  "Invalid JSON (#{e}): #{@payload_raw}"
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication requires that you construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app an not altererd by
    # a malicious third party.
    def authenticate_app
      payload = {
          # The time that this JWT was issued, _i.e._ now.
          iat: Time.now.to_i,

          # JWT expiration time (10 minute maximum)
          exp: Time.now.to_i + (10 * 60),

          # Your GitHub App's identifier number
          iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client, authenticated as an installation of a
    # GitHub App, to run API operations.
    def authenticate_installation(payload)
      @installation_id = payload['installation']['id']
      @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    # Check X-Hub-Signature to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub uses the WEBHOOK_SECRET, registered to the GitHub App, to
    # create the hash signature sent in the `X-HUB-Signature` header of each
    # webhook. This code computes the expected hash signature and compares it to
    # the signature sent in the `X-HUB-Signature` header. If they don't match,
    # this request is an attack, and you should reject it. GitHub uses the HMAC
    # hexdigest to compute the signature. The `X-HUB-Signature` looks something
    # like this: "sha1=123456".
    # See https://developer.github.com/webhooks/securing/ for details.
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end

  end

  # Finally some logic to let us run this server directly from the command line,
  # or with Rack. Don't worry too much about this code. But, for the curious:
  # $0 is the executed file
  # __FILE__ is the current file
  # If they are the same—that is, we are running this file directly, call the
  # Sinatra run method
  run! if __FILE__ == $0
end
