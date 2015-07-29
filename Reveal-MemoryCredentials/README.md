Disclaimer

Any actions and or activities related to the material contained within this blog is solely your responsibility.The misuse of the information in this website can result in criminal charges brought against the persons in question. The authors will not be held responsible in the event any criminal charges be brought against any individuals misusing the information in this website to break the law.

This script is published for educational use only. I am no way responsible for any misuse of the information.

This article is related to Computer Security and I am not promote hacking / cracking / software piracy.

This article is not a GUIDE of Hacking. It is only provide information about the legal ways of retrieving the passwords. You shall not misuse the information to gain unauthorised access. However you may try out these hacks on your own computer at your own risk. Performing hack attempts (without permission) on computers that you do not own is illegal.

# RWMC
Powershell - Reveal Windows Memory Credentials 

The purpose of this script is to make a proof of concept of how retrieve Windows credentials 
with Powershell and CDB Command-Line Options (Windows Debuggers) 

It allows to retrieve credentials from windows 2003 to 2012 (it was tested on 2003, 2008r2, 2012, 2012r2 and Windows 7 - 32 and 64 bits and Windows 8).

It works even if you are on another architecture than the system targeted.
# Quick usage

Launch the script (example for a D:\2008_20150618154432\lsass.dmp from a 2008r2 server)

 \
  \ /\   Follow the white Rabbit :-)
  ( )       Pierre-Alexandre Braeken
.( @ ). 

Mode (1, 2 or 3)?: 2      [enter]

gen = local credentials dump __ or __ file name of a dump __ or __ nothing -> "": D:\2008_20150618154432       [enter]

Name of the remote server (if second parameter = ""):      [enter]

--> a notepad open with the credentials found


# Never ever give administrator access to your user

# Always audit what you sysadmin or provider are doing on your systems 

To run effectively this script you need two things :

To run effectively this script you need :

* PowerShell 3
* Allow PowerShell script on you machine, example : Set-ExecutionPolicy Unrestricted -force
* An Internet connection

The script was tested on a 7 and on a 8 machine to retrieve password from Windows Server 2003,2008R2,2012,7 and 8.

