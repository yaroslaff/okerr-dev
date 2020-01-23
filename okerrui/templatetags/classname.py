from django.template.defaulttags import register

@register.filter
def classname(obj):
    return obj.__class__.__name__


