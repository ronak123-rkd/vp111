from django.db import models
from django.contrib.auth.models import AbstractUser


class CustomUser(AbstractUser):
    username = models.CharField('username', max_length=250)
    email = models.EmailField('email address', unique=True)
    first_name = models.CharField('First Name', max_length=255, blank=True,null=False)
    last_name = models.CharField('Last Name', max_length=255, blank=True,null=False)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name','username']

    def __str__(self):
        return f"{self.email} - {self.first_name} {self.last_name}"

