## Convert mRemoteNG Database to keepass
This is a valuable python script that can help you to migrate your mRemoteNG connections to KeePass
### What is mRemoteNG ?
[mRemoteNG](https://mremoteng.org/) is a fork of mRemote: an open source, tabbed, multi-protocol, remote connections manager for Windows. mRemoteNG adds bug fixes and new features to mRemote and allows you to view all of your remote connections in a simple yet powerful tabbed interface.
### What is KeePass ?
[KeePass](https://keepass.info/) is a free open source password manager, which helps you to manage your passwords in a secure way. You can store all your passwords in one database, which is locked with a master key. So you only have to remember one single master key to unlock the whole database. Database files are encrypted using the best and most secure encryption algorithms currently known (AES-256, ChaCha20 and Twofish)
### Why born mRemoteNG to KeePass?
I used mRemoteNG from about Six years ago until today, Recently I decided to remove it and use the other tools to manage my connections.
this means I have near 600 remote connections In mRemoteNG so I should find a solution to save my data or migrate these to my new connection manager, unfortunately, mRemoteNG has not any tools or solutions to export my connections without encrypted passwords, after many searches I see many people have my problem so I working on it and made "mRemoteNG To KeePass" finally

#### what assets will be moved?
First Of all, I should say all your connections will be moved recursively and sorts the same as your mRemoteNG GUI, in countinue the bellow data will be moved to your keepass : 
mRemoteGN Directory moved as Group in to KeePass
Connection Name moved as Item title in to KeePass
Connection Hostname and Connection Port moved as url:port in to KeePass
Connection Description moved as Notes in to KeePass

### installation

```
git clone https://github.com/momohammadi/mRemoteNG_To_Keepass.git
cd mRemoteNG_To_Keepass && sudo pip install -r requirements.txt
```
### usage
1. export mRemoteNG database as XML File 
2. run bellow command
```bash
python mRemoteNG_To_Keepass.py -f XMLFILEPATH.xml -o OUTPOUTPATH.csv -p YourMreotengMasterPassword
```
3. Open KeePass or KeePassxc and import CSV output to it and Finished!

#### Option explains:
```
  -h, --help            show this help message and exit
  -f XML_DB, --xml_db XML_DB
                        mRemoteNG XML configuration file
  -p PASSWORD, --password PASSWORD
                        Optional decryption password
  -o OUTPUT_FILE, --output_file OUTPUT_FILE
                        output file path
```

thank's to [haseebT](https://github.com/haseebT) for mRemoteNG-Decrypt Repository
