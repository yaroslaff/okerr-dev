from django.contrib import admin

"""
from okerrui.models import (
    Membership,
    Indicator,
    Policy, 
    Profile,
    ProjectTextID,
    CheckArg,
    CheckMethod
    )
from okerrui.bonuscode import BonusCode, BonusActivation
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    
class UserAdmin(UserAdmin):
    inlines = (ProfileInline, )



class CAInline(admin.TabularInline):
    model = CheckArg
    can_delete = True
    
class CheckMethodAdmin(admin.ModelAdmin):
    inlines = (CAInline, )



class IndicatorAdmin(admin.ModelAdmin):
    fields=['name','desc','status','substatus','policy','updated','changed','user']

class CheckArgAdmin(admin.ModelAdmin):
    list_display = ('argname','cm','default')

admin.site.register(Membership)
admin.site.register(Profile)
admin.site.register(Indicator,IndicatorAdmin)
admin.site.register(Policy)
admin.site.register(BonusCode)
admin.site.register(ProjectTextID)
admin.site.register(CheckArg,CheckArgAdmin)
admin.site.register(CheckMethod,CheckMethodAdmin)
admin.site.unregister(User)
admin.site.register(User, UserAdmin)
"""
