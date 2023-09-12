from rest_framework import serializers
from .models import ipClass

class ipSerializer(serializers.ModelSerializer):
    class Meta:
        model = ipClass
        fields = ['title']