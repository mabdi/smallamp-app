require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements

class GHAapp < Sinatra::Application

  helpers do

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

