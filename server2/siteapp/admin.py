from django.apps import apps
from django.contrib import admin
from .models import Post
from .models import Document


# Register your models here.
for model in apps.get_app_config('siteapp').get_models():
    admin.site.register(model)
