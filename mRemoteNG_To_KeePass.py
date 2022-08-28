#!/usr/bin/env python3
import argparse
import csv
import re
import base64
import sys
import hashlib
import xml.etree.ElementTree as ET
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# MAIN #########################################################################
parser = argparse.ArgumentParser(description = 'Decrypt mRemoteNG and Convert to a CSV with KeePass Compatibility',exit_on_error=True)
parser.add_argument('-f', '--xml_db', type=str, help='mRemoteNG XML configuration file')
parser.add_argument('-p', '--password', type=str, default='mR3m', help='Optional decryption password')
parser.add_argument('-o', '--output_file', type=str, default='keepassxc.csv', help='output file path')
args = parser.parse_args()

try:
    with open(args.xml_db, 'r') as f:
        conf = f.read()
except:
    print('Argument Error : mRemoteNG XML not valid')
    parser.print_help() 
    exit(0)

# DECRYPTION ###################################################################
def decrypt(mode, data, password):
    if (mode == 'CBC'):
        return cbc_decrypt(data, password)
    if (mode == 'GCM'):
        return gcm_decrypt(data, password)
    raise ValueError(f'unkown mode {mode}') ;

def gcm_decrypt(data, password):
    salt = data[:16]
    nonce = data[16:32]
    ciphertext = data[32:-16]
    tag = data[-16:]
    # TODO: get these values from the config file
    key = hashlib.pbkdf2_hmac('sha1', password, salt, 1000, dklen=32)   # default values
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(salt)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()
    except ValueError:
        print('MAC tag not valid, this means the master password is wrong or the crypto values aren\'t default')
        exit(1)
    return plaintext

def cbc_decrypt(data, password):
    iv = data[:16]
    ciphertext = data[16:]
    key = hashlib.md5(password).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# OUTPUT #######################################################################
outputFile = open(args.output_file,'w')
def print_output(groupName, title, username, password, url, notes):
        outputFile.write( groupName + ',' + title + ',' + username + ',' + password + ',' + url + ',' + notes + '\n')        

# Build CSV From XML ###########################################################
def crawlXml(xmlString,nodes=None,name=None): 
    root = ET.fromstring(xmlString)
    if(nodes == None):
        nodes = root.findall('Node')        
    for mainNodes in nodes:
        nodeType    = mainNodes.get('Type')   
        if(name != None and nodeType == 'Container'):
            nodeName    = name + '/' + mainNodes.get('Name')
            crawlXml(conf,mainNodes,nodeName)
        elif(nodeType == 'Container'):
            nodeName    = mainNodes.get('Name')
            crawlXml(conf,mainNodes,nodeName)
        elif(nodeType == 'connection' and name != None):
            nodeName    = name
        
        if('nodeName' in locals()):
            groupName = nodeName
        elif(name != None):
            groupName = name
        else:
            groupName = 'RootDirectory'
        title       = mainNodes.get('Name')          
        username    = mainNodes.get('Username')
        hostname    = mainNodes.get('Hostname')
        url         = hostname + ':' + mainNodes.get('Port')
        notes       = 'Connection Description : ' + mainNodes.get('Descr') if mainNodes.get('Descr') else ''
        notes       += ' Protocol : ' +  mainNodes.get('Protocol')
        data        = base64.b64decode(mainNodes.get('Password'))            
        password    = ""
        if data != b'':
            password=decrypt(mode, data, args.password.encode())
        if(password):
            print_output(groupName,title,username,password,url,notes)

mode = re.findall('BlockCipherMode="([^"]*)"', conf)
if not mode:
    mode = 'CBC'            # <1.75 key is md5(password) and encryption is CBC
elif mode[0] == 'GCM':
    mode = 'GCM'            # >=1.75 key is PBKDF2(password) and encryption is GCM
else:
    print('Unknown mode {}, implement it yourself or open a ticket'.format(mode[0]))
    sys.exit(1)

# Extract and decrypt file data if FullFileEncryption is true
full_encryption = re.findall('FullFileEncryption="([^"]*)"', conf)

if full_encryption and (full_encryption[0] == 'true'):
    cypher=base64.b64decode(re.findall('<.*>(.+)</mrng:Connections>', conf)[0]) 
    conf=decrypt(mode, cypher, args.password.encode())

crawlXml(conf)
outputFile.close()