
# coding=utf-8

from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from okerrui.models import (
    CheckMethod,
    Indicator,
    Policy,
    Profile,
    Project,
    Group,
    CheckMethod
)
import datetime



class IndicatorTestCase(TestCase):
    def setUp(self):    
        User = get_user_model()
        self.user = User.objects.get(username='test@example.com')
        self.profile = self.user.profile
        self.project = Project.objects.get(owner=self.user,name='test@example.com')


    @classmethod
    def setUpClass(cls):
        User = get_user_model()    

        # create database        
        Group.reinit_groups(delete=None, readonly=False, quiet=True)
        CheckMethod.reinit_checkmethods(really=True, quiet=True)

        # create test user
        user = User.objects.create(username='test@example.com')
        profile = Profile.objects.create(user = user)
        profile.inits()
        profile.save()
        profile.assign(group='Cursa', time=datetime.timedelta(hours=1))
        
        project = Project.objects.get(owner=user,name='test@example.com')
        
        policy_noretry = Policy(project=project,name='noretry')
        policy_noretry.retry_schedule = ''
        policy_noretry.save()
        


    @classmethod
    def tearDownClass(cls):
        pass

    def test_cyrname(self):
        iname = u'ляля'
        i2name = u'маляля'
        i = Indicator.create(self.project,iname,silent=True)
        i.copy(i2name)
        i2 = self.project.get_indicator(i2name)
        print i2
        self.assertIsInstance(i2, Indicator)

    def test_heartbeat(self):
        # project = Project.objects.get(owner=self.user,name='test@example.com')
        # policy = Policy.objects.get(project=project,name='Default')
        iname='hbtest'

        i = Indicator.create(self.project,iname,silent=True)

        Indicator.update(self.project,iname,status='OK')
        i = self.project.get_indicator(iname)
        self.assertEqual(i.status,'OK')

        Indicator.update(self.project,iname,status='ERR')
        i = self.project.get_indicator(iname)
        self.assertEqual(i.status,'ERR')
        
        
        Indicator.update(self.project,iname,status='OK')
        i = self.project.get_indicator(iname)
        self.assertEqual(i.status,'OK')
                
                
    def test_num(self):
        project = self.project
        policy = Policy.objects.get(project=project,name='noretry')
        iname='numtest'

        i = Indicator.create(project,iname,cmname='numerical',policy='noretry', silent=True)        
        
        # usual update
        Indicator.update(project,iname,status='22')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')


        # minlim check
        i.setdefargs()
        i.setarg('minlim', 100)
        i.save()
        Indicator.update(project,iname,status='99')
        i = project.get_indicator(iname)
        print i,i.getarg('current'), i.getarg('minlim')
        
        self.assertEqual(i.status,'ERR')

        Indicator.update(project,iname,status='100')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')

        # maxlim check
        i.setdefargs()
        i.setarg('maxlim',1000)
        i.save()
        Indicator.update(project,iname,status='1000')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')
        Indicator.update(project,iname,status='1001')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'ERR')


        # devup abs check
        i.setdefargs()      
        i.setarg('diffmax',100)
        i.save()
        
        Indicator.update(project,iname,status='1000')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')
        
        Indicator.update(project,iname,status='1001')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')
        
        # step 100, exactly OK
        Indicator.update(project,iname,status='1000')
        Indicator.update(project,iname,status='1100')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')
                                       
        # step 101, ERR
        Indicator.update(project,iname,status='1000')
        Indicator.update(project,iname,status='1101')
        i = project.get_indicator(iname)        
        print i, i.getarg('current')
        self.assertEqual(i.status,'ERR')
                                      
                                      
        # devup %% check
        i.setdefargs()      
        i.setarg('devup','10%')
        
        Indicator.update(project,iname,status='1000')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')
                                       
        Indicator.update(project,iname,status='1100')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')
                                       
        Indicator.update(project,iname,status='1000')
        Indicator.update(project,iname,status='1101')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'ERR')
                                       
                                       
        # devdown abs check
        i.setdefargs()      
        i.setarg('diffmin',-10)
        i.save()
        Indicator.update(project,iname,status='1000')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')
        
        Indicator.update(project,iname,status='990')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')
        
        # step 101, ERR
        Indicator.update(project,iname,status='1000')
        Indicator.update(project,iname,status='989')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'ERR')

        # devdown %% check
        i.setdefargs()      
        i.setarg('diffmin','-10%')
        i.save()
        Indicator.update(project,iname,status='1000')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')
        
        Indicator.update(project,iname,status='900')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'OK')

        Indicator.update(project,iname,status='1000')
        Indicator.update(project,iname,status='899')
        i = project.get_indicator(iname)
        print i,i.getarg('current')
        self.assertEqual(i.status,'ERR')


