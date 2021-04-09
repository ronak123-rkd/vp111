from .utils import get_and_authenticate_user, create_user_account
from . import serializers
from django.contrib.auth import get_user_model,logout
from django.core.exceptions import ImproperlyConfigured
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.response import Response
from django.shortcuts import render,redirect
from django.conf import settings
from .serializers import UserRegisterSerializer
from django.shortcuts import render,redirect
from django.core.mail import send_mail
from django.contrib.auth import login,authenticate

User = get_user_model()


class AuthViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny, ]
    serializer_class = serializers.EmptySerializer
    serializer_classes = {
        'login': serializers.UserLoginSerializer,
        'register': serializers.UserRegisterSerializer,
        'password_change': serializers.PasswordChangeSerializer,
    }

    @action(methods=['POST', ], detail=False)
    def login(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = get_and_authenticate_user(**serializer.validated_data)
        data = serializers.AuthUserSerializer(user).data

        return Response(data=data, status=status.HTTP_200_OK)

    @action(methods=['POST', ], detail=False)
    def register(self, request):
        subject = "Thank you for registering to our site"
        message = "You have succesfully created an account"
        email_from = settings.EMAIL_HOST_USER
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = create_user_account(**serializer.validated_data)
        data = serializers.UserRegisterSerializer(user).data
        email = data.get('email')
        recipient_list = [email, ]
        send_mail(subject, message, email_from, recipient_list)
        return Response(data=data, status=status.HTTP_201_CREATED)

    @action(methods=['POST'], detail=False, permission_classes=[IsAuthenticated, ])
    def password_change(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['POST', ], detail=False)
    def logout(self, request):
        logout(request)
        data = {'success': 'Sucessfully logged out'}
        return Response(data=data, status=status.HTTP_200_OK)

    def get_serializer_class(self):
        if not isinstance(self.serializer_classes, dict):
            raise ImproperlyConfigured("serializer_classes should be a dict mapping.")

        if self.action in self.serializer_classes.keys():
            return self.serializer_classes[self.action]
        return super().get_serializer_class()

   # @action(methods=['POST', ], detail=False)
    #def mail(request):
       # subject = "real programmer welcome mail"
        #msg = "congratulations for mail"
       # to = "ronak@aagammedia.com"
       # res = send_mail(subject,msg,settings.EMAIL_HOST_USER, [TO])
       # if(res == 1):
        #    msg = "Mail sent"
        #else:
           # msg = "Mail could not send"
        #return msg


#class VerifyEmail(viewsets.GenericViewSet):
   # def get(self):
       # pass
#from django.core.mail import send_mail
#from rest_framework_simplejwt.tokens import RefreshToken
#from .utils import Util
#from django.contrib.sites.shortcuts import get_current_site
#from django.urls import reverse


 #########user = User.objects.get(email=user_data['eamil'])
       ######## token = RefreshToken.for_user(user).access_token
       ####### current_site=get_current_site(request).domain
       ###### relativeLink = reverse('users:email-varify')
        ######absurl= 'http://'+current_site+relativeLink+"?token"=+str(token)
        ####email_body= 'Hi'+user.username+' Use link below to verify your email \n'#+ absurl
        ###data = {'email_body':email_body, 'to_email':user.email,'email_subject': 'Verify your email'}
       ## Util.send_email()


