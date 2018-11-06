import logging
import requests
import urllib.parse
from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import redirect
from django.shortcuts import HttpResponseRedirect, HttpResponse
from django.views.decorators.http import require_http_methods
from github import Github
from oauth.models import Oauth

logger = logging.getLogger('app')
config = settings.CONFIG


def do_oauth(request):
    """
    # View  /oauth/
    """
    oauth = Oauth.objects.all()[0]
    request.session['login_redirect_url'] = get_next_url(request)
    params = {
        'client_id': oauth.client_id,
        'scope': oauth.scope,
        'redirect_uri': oauth.redirect_uri,
    }
    url_params = urllib.parse.urlencode(params)
    new_uri = 'https://github.com/login/oauth/authorize?{}'.format(url_params)
    return HttpResponseRedirect(new_uri)


def callback(request):
    """
    # View  /oauth/callback/
    """
    try:
        oauth_code = request.GET['code']
        access_token = get_token(oauth_code)
        github_profile = get_profile(access_token)
    except Exception as error:
        logger.exception(error)
        err_msg = 'Fatal Login Error. Report as Bug: %s' % error
        return HttpResponse(err_msg, content_type='text/plain')

    auth = login_user(request, github_profile)
    if not auth:
        err_msg = 'Unable to complete login process. Report as a Bug.'
        return HttpResponse(err_msg, content_type='text/plain')

    try:
        next_url = request.session['login_redirect_url']
    except:
        next_url = '/'
    return HttpResponseRedirect(next_url)


@require_http_methods(['POST'])
def log_out(request):
    """
    View  /oauth/logout/
    """
    # next_url = get_next_url(request)
    logout(request)
    # request.session['login_next_url'] = next_url
    # return redirect(next_url)
    return redirect('home.index')


def login_user(request, data):
    """
    Login or Create New User
    """
    try:
        user = User.objects.filter(username=data['username']).get()
        user = update_profile(user, data)
        user.save()
        login(request, user)
        return True
    except ObjectDoesNotExist:
        user = User.objects.create_user(data['username'], data['email'])
        user = update_profile(user, data)
        user.save()
        login(request, user)
        return True
    except Exception as error:
        logger.exception(error)
        return False


def get_token(code):
    """
    Post OAuth code to GitHub and return access_token
    """
    oauth = Oauth.objects.all()[0]
    url = 'https://github.com/login/oauth/access_token'
    data = {
        'client_id': oauth.client_id,
        'client_secret': oauth.client_secret,
        'code': code,
    }
    headers = {'Accept': 'application/json'}
    r = requests.post(url, data=data, headers=headers, timeout=10)
    return r.json()['access_token']


def get_profile(access_token):
    """
    Get GitHub Profile and Emails
    """
    gh = Github(access_token)
    gh_user = gh.get_user()
    return {
        'username': gh_user.login,
        'email': get_gh_email(gh_user),
        'access_token': access_token,
        'github_id': gh_user.id,
        'avatar_url': gh_user.avatar_url,
        'html_url': gh_user.html_url,
    }


def update_profile(user, data):
    """
    Update user_profile from GitHub data
    """
    user.profile.access_token = data['access_token']
    user.profile.github_id = data['github_id']
    user.profile.avatar_url = data['avatar_url']
    user.profile.html_url = data['html_url']
    user.email = data['email']
    return user


def get_gh_email(gh_user):
    """
    1st Returns GitHub email if it can be found else None
    2nd Returns True or False if it is found or not
    """
    emails = gh_user.get_emails()
    for email in emails:
        if 'primary' in email:
            if email['primary']:
                if 'email' in email:
                    return email['email']
    for email in emails:
        if 'verified' in email:
            if email['verified']:
                if 'email' in email:
                    return email['email']
    for email in emails:
        if 'email' in email:
            if email['email']:
                return email['email']
    return None


def get_next_url(request):
    """
    Determine 'next' Parameter
    """
    try:
        next_url = request.GET['next']
    except:
        try:
            next_url = request.POST['next']
        except:
            try:
                next_url = request.session['login_next_url']
            except:
                next_url = '/'
    if not next_url:
        next_url = '/'
    return next_url
