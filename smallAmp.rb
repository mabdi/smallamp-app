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

  WORKFLOW_FILE = '.github/workflows/SmallAmpCI.yml'
  SMALLAMP_REPOS = '~/smallampfiles/'

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

  helpers do

    def handle_action_completed(payload)
        if payload["workflow"]["path"] != WORKFLOW_FILE 
            logger.debug 'another workflow has been finished, none of our business! ' + payload["workflow"]["path"]
            return
        end 
        if payload["workflow_run"]["conclusion"] != "success"
            logger.debug 'The job has failed. skip it ' + payload["workflow_run"]["conclusion"]
            return
        end
        artifacts = @installation_client.get(payload["workflow_run"]["artifacts_url"])
        folder = SMALLAMP_REPOS + payload["repository"]["full_name"] + "/workflows/" + payload["workflow_run"]["run_number"] 
        FileUtils.mkdir_p folder
        artifacts["artifacts"] do | art |
            zip = @installation_client.get art["archive_download_url"]
            File.open(folder + "/" + art["name"] + ".zip", "wb") do |f|
               f.write(zip)
            end
            logger.debug "zip created: " + folder + "/" + art["name"] + ".zip"
        end
    end

    def handle_repo_install(repo_list)
          logger.debug 'handle_repo_install'
          handle_repo_install_repo(repo_list[0])
    end

    def handle_repo_install_repo(rp)
       logger.debug rp
       r = @installation_client.repo(rp['full_name'])
       begin
          @installation_client.contents( rp['full_name'], :path => WORKFLOW_FILE)
          logger.debug 'CI file exists, skip'
          return
       rescue Octokit::NotFound
          logger.debug 'not found, lets add it'
          my_content = File.read('SmallAmpCI.yml')
          @installation_client.create_contents(rp['full_name'],
                 WORKFLOW_FILE,
                 "[SmallAmpApp] push SmallAmpCI.yml",
                 my_content,
                 :branch => r.default_branch)
       end
    end


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
  # If they are the same???that is, we are running this file directly, call the
  # Sinatra run method
  run! if __FILE__ == $0
end
