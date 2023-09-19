from django.shortcuts import render
from rest_framework.views import APIView
from .models import ipClass
from .serializer import ipSerializer
from rest_framework.response import Response
import socket
import json
import requests
from geopy.geocoders import Nominatim
import os

###IP###
def validateIP(str):
    pointCounter = 0
    for letter in str:
        if letter == ".":
            pointCounter += 1
    if pointCounter == 3:
        try: 
            socket.inet_aton(str)
            return True
        except:
            return False
    else:
        return False

def getIP1(ip):
    response = requests.get(url=f'http://ip-api.com/json/{ip}').json()
    geolocator = Nominatim(user_agent="views")
    address = str(geolocator.reverse(str(response["lat"])+","+str(response["lon"])))
    data = {
        "country": response["country"],
        "region": response["regionName"],
        "city": response["city"],
        "zip": response["zip"],
        "prov": response["isp"],
        "lon": response["lon"],
        "lat": response["lat"],
        "addr": address
    }
    return data
def getIP2(ip):
    response = requests.get(url = f"https://ipinfo.io/{ip}/json").json()
    geolocator = Nominatim(user_agent="views")
    address = str(geolocator.reverse(str(response["loc"])))
    data = {
        "country": response["country"],
        "region": response["region"],
        "city": response["city"],
        "zip": response["postal"],
        "prov": response["org"],
        "lon": response["loc"].split(",")[1],
        "lat": response["loc"].split(",")[0],
        "addr": address
    }
    return data

class ipInformationView(APIView):
    def get(self, request):
        return Response({})
    
    def post(self, request):
        ipStr = request.data["ip"]
        try:
            if validateIP(ipStr):
                return Response({
                    "result": True, 
                    "data1": getIP1(ipStr),
                    "data2": getIP2(ipStr)
                })
            else:
                return Response({
                    "result": False
                })
        except:
            return Response({
                "result": False
            })
###IP###

###history###
class historyView(APIView):
    def get(self, request):
        try:
            with open("history.json", "r") as file:
                dataJson = json.loads(file.read())
            history = dataJson["history"]
        except ValueError as er:
            print(er)
        return Response({
            "result": json.dumps(history)
        })

    def post(self, request):
        with open("history.json", "r") as file:
            dataJson = json.loads(file.read())
            dataJsonArr = dataJson["history"]
            if len(dataJsonArr) == 10:
                del dataJsonArr[0]
        dataJsonArr.append({
            "type": request.data["type"],
            "target": request.data["target"],
            "timePoint": request.data["timePoint"]
        })
        with open ("history.json", "w") as file:
            file.write(json.dumps(dataJson))
        return Response({
            "result":123
        })
###history###
