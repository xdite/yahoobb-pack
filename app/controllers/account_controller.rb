class AccountController < ApplicationController

  def yahooLogin
    ya = YahooBbAuth.new()
    redirect_to ya.get_auth_url('', true)
  end

  def yahooAuth

    ya = YahooBbAuth.new()

    userhash = params[:userhash]
    if !ya.verify_sig(request.request_uri)
      redirect_to :controller => :error
    return
    end

    @user = User.find_by_yahoo_userhash(userhash)
    @userhash = userhash
    if @user == nil
      @user = User.new(:yahoo_userhash => userhash)
      render :template => 'users/fillup'
    else
      self.current_user = @user
      redirect_back_or_default('/')
    end
  end
  
end
