from django import http
# obsolete:
# from django.utils.http import urlquote
# from urllib.parse import quote
from django import urls
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin


class LSlashMiddleware(MiddlewareMixin):
    """
    remove extra leading slashes, e.g. convert //api/director/zzzz to /api/director/zzz
    
    Based on gregbrown.co.nz/code/append-or-remove-slash/ for more information."""

    def process_request(self, request):

        # check if the url is valid
        urlconf = getattr(request, 'urlconf', None)
        if not _is_valid_path(request.path_info, urlconf):
            # if not, check if removing exra-leading slashes helps
            if request.path_info.startswith('//'):
                new_path_info = '/' + request.path_info.lstrip('/')
                if _is_valid_path(new_path_info, urlconf):
                    request.path_info = new_path_info


def _is_valid_path(path, urlconf=None):
    """
    Returns True if the given path resolves against the default URL resolver,
    False otherwise.
    """
    try:
        urls.resolve(path, urlconf)
        return True
    except urls.Resolver404:
        return False
