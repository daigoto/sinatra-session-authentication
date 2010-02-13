require 'sinatra/base'
require 'sequel'
require 'digest/sha1'

module Sinatra
  module SessionAuthentication
    VERSION = "0.0.1"
    def self.registered(app)

      get '/account' do
        if logged_in?
          me = session[:id]
        else
          me = nil
        end
        if me.nil?
          redirect '/account/signup'
        else
          redirect '/account/' + me.to_s
        end
      end

      get '/account/login' do
        erb :account_login, :layout => use_layout?
      end

      post '/account/login' do
        if (user = authenticate(params[:account], params[:password])) != nil
          # change session id if logged in
          env['rack.session.options'].merge!(:renew => true) 
          session[:id] = user[:id]
          session[:user] = user
          if session[:return_to]
            redirect session[:return_to]
            session[:return_to] = nil
          else
            redirect '/'
          end
        else
          # login failure
          erb :account_login, :layout => use_layout?
        end
      end

      get '/account/logout' do
        # change session id if logged in
        env['rack.session.options'].merge!(:renew => true) 
        session[:id] = nil
        session[:user] = nil
        session[:return_to] = nil
        redirect '/'
      end

      get '/account/signup' do
        erb :account_signup, :layout => use_layout?
      end

      post '/account/signup/confirm' do
        begin
          # Validate as you need
          raise if params[:password] != params[:password_confirm]
          @token = encrypt(params[:account], DateTime.now.to_s)
          session[:token] = @token
          env['rack.session.options'].merge!(:defer => false)
          erb :account_signup_confirm, :layout => use_layout?
        rescue
          warn $!.inspect
          erb :account_signup, :layout => use_layout?
        end
      end
      
      post '/account/signup/end' do
        begin
          raise if session[:token] != params[:token]
          # Validate as you need
          DB[:user] << { :account   => params[:account],
                         :password  => encrypt(params[:account], params[:password])
                       }
          # change session id if logged in
          env['rack.session.options'].merge!(:renew => true) 
          user = DB[:user].find(:account => params[:account]).first
          session[:id] = user[:id]
          session[:user] = user
          session[:token] = nil
          session[:return_to] = nil
          erb :account_signup_end, :layout => use_layout?
          
        rescue
          warn $!.inspect
          session[:token] = nil
          env['rack.session.options'].merge!(:defer => false)
          erb :account_signup, :layout => use_layout?
        end
      end

      get '/account/:id/edit' do
        login_required
        redirect "/account" unless is_current_user(params[:id])
        @user = DB[:user].first(:id => params[:id]).first
        erb :account_edit, :layout => use_layout?
      end

      post '/account/:id/edit/confirm' do
        login_required
        redirect "/account" unless is_current_user(params[:id])
        
        begin
          # Validate as you need
          raise unless authenticate(session[:user][:account], params[:password_old])
          raise if params[:password] != params[:password_confirm]
          
          @token = encrypt(session[:user][:account], DateTime.now.to_s)
          session[:token] = @token
          env['rack.session.options'].merge!(:defer => false)
          erb :account_edit_confirm, :layout => use_layout?
        rescue
          warn $!.inspect
          erb :account_edit, :layout => use_layout?
        end
      end

      post '/account/:id/edit/end' do
        env['rack.session.options'].merge!(:defer => false)
        begin
          login_required
          redirect "/account" unless is_current_user(params[:id])
          raise if session[:token] != params[:token]

          DB[:user].filter(:id => params[:id]).update(
            :password  => encrypt(session[:user][:account], params[:password])
          )
          @user = DB[:user].find(:id => params[:id]).first
          session[:user] = @user
          session[:token] = nil
          redirect "/account/" + params[:id].to_s 
        rescue
          warn $!.inspect
          env['rack.session.options'].merge!(:defer => false)
          session[:token] = nil
          erb :account_edit, :layout => use_layout?
        end
      end

      get '/account/:id/delete' do
        login_required
        redirect "/account" unless is_current_user(params[:id])
        erb :account_delete, :layout => use_layout?
      end
      
      post '/account/:id/delete/confirm' do
        login_required
        redirect "/account" unless is_current_user(params[:id])
        
        begin
          # Validate as you need
          @token = encrypt(session[:user][:account], DateTime.now.to_s)
          session[:token] = @token
          env['rack.session.options'].merge!(:defer => false)
          erb :account_delete_confirm, :layout => use_layout?
        rescue
          warn $!.inspect
          erb :account_delete, :layout => use_layout?
        end
      end

      post '/account/:id/delete/end' do
        env['rack.session.options'].merge!(:defer => false)
        begin
          login_required
          redirect "/account" unless is_current_user(params[:id])
          raise if session[:token] != params[:token]
          
          DB[:user].filter(:id => params[:id]).delete
          # change session id if logged in
          env['rack.session.options'].merge!(:renew => true) 
          session[:id] = nil
          session[:user] = nil
          session[:token] = nil
          session[:return_to] = nil
          erb :account_delete_end, :layout => use_layout?
        rescue
          warn $!.inspect
          session[:token] = nil
          erb :account_delete, :layout => use_layout?
        end
      end
      
      get '/account/:id' do
        @user = DB[:user].find(:id => params[:id]).first
        erb :account_show, :layout => use_layout?
      end
      
    end
  end
  
  module Helpers
    include Rack::Utils
    alias_method :h, :escape_html
    alias_method :e, :escape
    alias_method :u, :unescape
    
    def login_required
      if session[:user]
        return true
      else
        env['rack.session.options'].merge!(:defer => false)
        session[:return_to] = request.fullpath
        redirect '/account/login'
        return false
      end
    end

    def is_current_user(id)
      if session[:id].to_i == id.to_i
        true
      else
        false
      end
    end

    def logged_in?
      session[:user]
    end

    def use_layout?
      !request.xhr?
    end

    def encrypt(account, pass)
      ::Digest::SHA1.hexdigest(pass+account)
    end
    
    def authenticate(account, pass)
      current_user = DB[:user].filter(:account => account).first
      if current_user.nil? == false && encrypt(account, pass) == current_user[:password]
        return current_user
      end
      nil
    end 
  end
  register SessionAuthentication
end

