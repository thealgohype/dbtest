from .models import *
from .serializers import *
from .services import *
from django.conf import settings
from django.shortcuts import redirect
from rest_framework.views import APIView
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from chaty.llm import LLMChain
from rest_framework.response import Response
from datetime import datetime
from google.cloud import texttospeech
from google.oauth2 import service_account
import os
from django.contrib.auth.decorators import login_required
from bson import ObjectId
import pytz
import base64
from .models import mytest
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny

User = get_user_model()

class GoogleLoginApi(APIView):
    def get(self, request, *args, **kwargs):
        auth_serializer = AuthSerializer(data=request.GET)
        auth_serializer.is_valid(raise_exception=True)
        
        validated_data = auth_serializer.validated_data
        user_data, jwt_token = createJwtToken(validated_data)
        
        response = redirect(settings.BASE_APP_URL)
        response.set_cookie('dsandeavour_access_token', jwt_token, max_age = 60 * 24 * 60 * 60)
        return response
    
    def post(self, request, *args, **kwargs):
        pass

@csrf_exempt
@api_view(['GET'])
def get_user_all_records(request):
    if request.method == 'GET':
        users = User.objects.all()
        if users.exists():
            response_data = [
                {
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                } for user in users
            ]
            return JsonResponse({'data': response_data}, safe=False, status=200)
        else:
            return JsonResponse({'message': 'No records found'}, status=200)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


