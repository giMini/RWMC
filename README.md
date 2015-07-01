# RWMC
Powershell - Reveal Windows Memory Credentials 
The purpose of this script is to make a proof of concept of how retrieve Windows credentials 
with Powershell and CDB Command-Line Options (Windows Debuggers) 

It allows to retrieve credentials from windows 2003 to 2012 (it was tested on 2003, 2008r2, 2012 and Windows 7 and Windows 8).

It works even if you are on another architecture than the system targeted.

# Never ever give administrator access to your user

# Always audit what you sysadmin or provider are doing on your systems 

To run effectively this script you need two things :

Allow Powershell script on you machine, example : Set-ExecutionPolicy Unrestricted -force

A Internet connection.

