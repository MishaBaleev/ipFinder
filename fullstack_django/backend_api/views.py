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
from whois import query
import validators
from scapy.all import *
from geopy.geocoders import Nominatim
import http.client as hClient

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
    geolocator = Nominatim(user_agent="ipFinder")
    address = geolocator.reverse(str(response["lat"])+","+str(response["lon"])).address
    data = {
        "country": response["country"],
        "region": response["regionName"],
        "city": response["city"],
        "zip": response["zip"],
        "prov": response["isp"],
        "lon": response["lon"],
        "lat": response["lat"],
        "address": address
    }
    return data
def getIP2(ip):
    response = requests.get(url = f"https://ipinfo.io/{ip}/json").json()
    geolocator = Nominatim(user_agent="ipFinder")
    address = geolocator.reverse(response["loc"]).address
    data = {
        "country": response["country"],
        "region": response["region"],
        "city": response["city"],
        "zip": response["postal"],
        "prov": response["org"],
        "lon": response["loc"].split(",")[1],
        "lat": response["loc"].split(",")[0],
        "address": address
    }
    return data

def getIP3(ip):
    response = requests.get(url = f"https://freeipapi.com/api/json/{ip}").json()
    geolocator = Nominatim(user_agent="ipFinder")
    address = geolocator.reverse(str(response["latitude"])+","+str(response["longitude"]), language="RU").address
    data = {
        "country": response["countryName"],
        "region": response["regionName"],
        "city": response["cityName"],
        "zip": response["zipCode"],
        "lon": response["longitude"],
        "lat": response["latitude"],
        "address": address
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
                    "data2": getIP2(ipStr),
                    "data3": getIP3(ipStr)
                })
            else:
                return Response({
                    "result": False
                })
        except ValueError as err:
            print(err)
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
        except:
            pass
        return Response({
            "result": json.dumps(history)
        })

    def post(self, request):
        with open("history.json", "r") as file:
            dataJson = json.loads(file.read())
        dataJsonArr = dataJson["history"]
        if len(dataJsonArr) == 20:
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
    
class historyDeleteView(APIView):
    def get(self, request):
        return Response({})
    def post(self, request):
        try:
            target = {
                "type": request.data["type"],
                "target": request.data["target"],
                "timePoint": request.data["timePoint"]
            }
            with open("history.json", "r") as file:
                dataJson = json.loads(file.read())
                dataJsonArr = dataJson["history"]
            if dataJsonArr.index(target) != -1:
                dataJsonArr.remove(target)
            with open("history.json", "w") as file:
                file.write(json.dumps(dataJson))
            return Response({
                "result": True,
                "data": dataJsonArr
            })
        except:
            return Response({
                "result": False
            })
###history###

###domain###
class domainInformationView(APIView):
    def get(self, request):
        return Response({})
    
    def post(self, request):
        if (validators.domain(request.data["target"]) == True):
            domain = query(request.data["target"]).__dict__
            # print(domain)
            try:
                searchResult = {
                    "ip": socket.gethostbyname(request.data["target"]),
                    "registrar": domain["registrar"],
                    "country": domain["registrant_country"],
                    "createDate": domain["creation_date"],
                    "expDate": domain["expiration_date"],
                    "org": domain["registrant"],
                    "nameservers": domain["name_servers"]
                }
                return Response({
                    "result": True,
                    "data": searchResult
                })
            except: 
                return Response({
                    "result": False
                })
        else:
           return Response({
               "result": False
           })
###domain###

###saveFile###
class saveToFileIP(APIView):
    def get(self, request):
        pass 

    def post(self, request):
        try:
            datas = {
                "data1": "IP-API",
                "data2": "IPINFO",
                "data3": "FreeIPAPI"
            }
            data = json.loads(request.data["data"])
            fileString = ""

            for key in data:
                fileString += datas[key] + "\n"
                for key2 in data[key]:
                    fileString += key2 + ": " + str(data[key][key2]) + "\n"
                fileString += "----------------" + "\n"

            with open(f"{os.getcwd().replace("fullstack_django", "IPReports")}/{request.data["timePoint"]}.txt", "w") as file:
                file.write(fileString)
                return Response({
                    "result": True,
                    "fileName": f"{request.data["timePoint"]}.txt"
                })
        except: 
            return Response({
                "result": False
            })
###saveFile###

###getMyIP###
class getMyIP(APIView):
    def get(self, request):
        conn = hClient.HTTPConnection("ifconfig.me")
        conn.request("GET", "/ip")
        result = conn.getresponse().read()
        return Response({
            "result": result
        })
    
    def post(self, request):
        pass
###getMyIP###