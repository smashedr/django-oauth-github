from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver


class Oauth(models.Model):
    client_id = models.CharField(max_length=255, help_text='Client ID.')
    client_secret = models.CharField(max_length=255, help_text='Client Secret.')
    redirect_uri = models.URLField(help_text='Redirect URL')
    scope = models.CharField(max_length=255, help_text='OAuth Scope')

    def __str__(self):
        return 'Oauth Settings'

    class Meta:
        verbose_name = 'Oauth'
        verbose_name_plural = 'Oauth'


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    access_token = models.CharField(max_length=80, blank=True, default='')
    github_id = models.IntegerField(blank=True, default=0)
    avatar_url = models.URLField(blank=True, default='')
    html_url = models.URLField(blank=True, default='')


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
