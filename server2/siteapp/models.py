from django.db import models


# Create your models here.
# class File(models.Model):
#     id = models.AutoField(primary_key=True)
#     filetype = models.CharField(default='', max_length=10)
#     md5 = models.TextField(default='')
#
#     def __str__(self):
#         return self.md5

class Post(models.Model):
    id = models.AutoField(primary_key=True)
    postname = models.CharField(max_length=100)
    contents = models.TextField()
    flag = models.BooleanField()
    


class Document(models.Model):
    id = models.AutoField(primary_key=True)
    docfile = models.FileField(upload_to='documents/%Y/%m/%d')
