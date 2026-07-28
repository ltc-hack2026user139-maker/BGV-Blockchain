#!/bin/bash
echo "34.72.224.210 peer0.org1.example.com" >> /etc/hosts
echo "34.72.224.210 peer0.org2.example.com" >> /etc/hosts
echo "34.72.224.210 orderer.example.com" >> /etc/hosts
exec python server.py
