#!/usr/bin/python
'''
PYRecon v0.2 - Copyright 2013 James Slaughter,
This file is part of PYRecon v0.2.

PYRecon v0.2 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

PYRecon v0.2 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with PYRecon v0.2.  If not, see <http://www.gnu.org/licenses/>.
 
'''

'''
pyrecon.py - This is the main file of the program and is the jumping off point
into the rest of the code
'''

#python imports
import sys
import os
import subprocess

#programmer generated imports
from argparser import argparser
from logreader import logreader
from fileio import fileio

'''
Usage()
Function: Display the usage parameters when called
'''
def Usage():
    print 'Usage: [required] --mode [optional] --target --supresswget --supressemail --debug --help'
    print 'Required Arguments:'
    print '--mode [auto, manual, fail2ban] - auto to be run as a scripted cron job, manual to be run as a one off and fail2ban to be run with Fail2ban'
    print 'Optional Arguments:'
    print '--target[Must be IP to work properly] - the host you \'re investigation - only use with fail2ban and manual modes'
    print '--supresswget - will not attempt a WGET against the target.'
    print '--supressemail - will not send out an e-mail summarizing the actions taken.'
    print '--debug - prints verbose logging to the screen to troubleshoot issues with a recon installation.'
    print '--help - You\'re looking at it!'
    sys.exit(-1)

'''
LogProcess()
Function: Reads in the /var/log.auth.log file and
processes it
'''
def LogProcess():
    LG.LogRead(AP.debug)


'''
Whois()
Function: Execute a whois against the provided domain
'''
def Whois(target, logdir):
    FI = fileio()
    filename = logdir + 'Whois.txt'

    if (AP.debug == True):
        print 'Whois domain: ' + target
         
    subproc = subprocess.Popen('whois '+target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for whois_data in subproc.stdout.readlines():
        AP.whois_output_data += whois_data
        if  (AP.debug == True):
            print whois_data

    FI.WriteFile(filename, AP.whois_output_data)


'''
NMap()
Function: Execute an NMap against the provided target
'''
def NMap(target, logdir):
    FI = fileio()
    filename = logdir + 'NMap.txt'

    if (AP.debug == True):
        print 'NMap: target: ' + target

    #NMap flags: -A Enable OS detection, version detection, script scanning, and traceroute
    #            -sV Probe open ports to determine service/version info   

    subproc = subprocess.Popen('nmap -A -sV '+target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for nmap_data in subproc.stdout.readlines():
        AP.nmap_output_data += nmap_data
        if (AP.debug == True):
            print nmap_data

    FI.WriteFile(filename, AP.nmap_output_data)
   

'''
WGet()
Function: Execute a WGet against the provided target
'''
def WGet(target, logdir):
    filename = logdir + 'index.html'

    if (AP.debug == True):
        print 'WGet: target: ' + target

    #WGet flags: --tries=5 Limit retries to a host connection to 5
    #            -S Show the original server headers
    #            -O output to given filename

    subproc = subprocess.Popen('wget --tries=5 -S -O ' + filename + ' ' + target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for wget_data in subproc.stdout.readlines():
        AP.wget_output_data += wget_data
        if (AP.debug == True):
            print wget_data

    filename = logdir + 'indexSSL.html'

    if (AP.debug == True):
        print 'WGet SSL: target: '+ target + ':443'

    #WGet flags: --tries=5 Limit retries to a host connection to 5
    #            -S Show the original server headers
    #            -O output to given filename
    

    subproc = subprocess.Popen('wget --tries=5 -S -O ' + filename + ' ' + target + ':443', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for wgetSSL_data in subproc.stdout.readlines():
        AP.wgetSSL_output_data += wgetSSL_data
        if (AP.debug == True):
            print wgetSSL_data

    filename = logdir + 'indexTomcat.html'

    if (AP.debug == True):
        print 'WGet Tomcat: target: '+ target + ':8080'

    #WGet flags: --tries=5 Limit retries to a host connection to 5
    #            -S Show the original server headers
    #            -O output to given filename

    subproc = subprocess.Popen('wget --tries=5 -S -O ' + filename + ' ' + target + ':8080', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for wgetTomcat_data in subproc.stdout.readlines():
        AP.wgetTomcat_output_data += wgetTomcat_data
        if (AP.debug == True):
            print wgetTomcat_data    


'''
Email()
Function: Send an Email summarizing the events 
'''
def Email(target, logdir):
    FI = fileio()
    filename = logdir + 'Msg.txt'
    
    email_output_data = ''

    email_output_data += 'To: ' + AP.emailrecp + '\n'
    email_output_data += 'From: ' + AP.emailsend + '\n'

    if (AP.mode == 'auto'):
        email_output_data += 'Subject: PYRecon Auto Run - IP: ' + target + '\n'
    elif (AP.mode == 'fail2ban'):
        email_output_data += 'Subject: PYRecon Fail2ban Alert - IP: ' + target + '\n'
    else:
        email_output_data += 'Subject: PYRecon Manual Run - IP: ' + target + '\n'

    email_output_data += '\n'
    email_output_data += 'Hi,\n'
    email_output_data += '\n'
    email_output_data += 'PYRecon has reviewed IP: ' + target + '\n'
    email_output_data += '\n'
    email_output_data += 'The results are as follows: \n'
    email_output_data += '\n'
    email_output_data += 'Whois\n'
    email_output_data += '---------\n'
    email_output_data += AP.whois_output_data + '\n'
    email_output_data += ' \n'
    email_output_data += 'Nmap\n'
    email_output_data += '---------\n'
    email_output_data += AP.nmap_output_data + '\n'
    email_output_data += '\n'
    email_output_data += 'WGet\n'
    email_output_data += '---------\n'
    email_output_data += AP.wget_output_data + '\n'
    email_output_data += '\n'
    email_output_data += 'WGet SSL\n'
    email_output_data += '---------\n'
    email_output_data += AP.wgetSSL_output_data + '\n'
    email_output_data += 'WGet Tomcat\n'
    email_output_data += '------------\n'
    email_output_data += AP.wgetTomcat_output_data + '\n'

    FI.WriteFile(filename, email_output_data)

    subproc = subprocess.Popen('ssmtp ' + AP.emailrecp + ' < ' + filename, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for email_data in subproc.stdout.readlines():
        if (AP.debug == True):
            print email_data

'''
Terminate()
Function: - Attempts to exit the program cleanly when called  
'''
     
def Terminate(exitcode):
    sys.exit(exitcode)

'''
This is the mainline section of the program and makes calls to the 
various other sections of the code
'''

if __name__ == '__main__':
    
        ret = 0
                    
        AP = argparser()
        ret = AP.Parse(sys.argv)
        
        if ret == -1:
            Usage()
            Terminate(ret)
            
        LG = logreader()
        LG.ConfRead(AP.debug)
        AP.logdir = LG.logdir
        AP.emailrecp = LG.emailrecp
        AP.emailsend = LG.emailsend
        
        if (len(LG.logdir) < 4):
            print 'The log directory has not been configured.  Please edit the pyrecon.conf file before continuing.'
            print ''
            Terminate(-1)
        elif (LG.logdir == '<log directory>'):
            print 'The log directory has not been configured.  Please edit the pyrecon.conf file before continuing.'
            print ''
            Terminate(-1)
        else:
            AP.logdir = LG.logdir.rstrip('\n')
            
        if (len(LG.emailrecp) < 4):
            print 'The log directory has not been configured.  Please edit the pyrecon.conf file before continuing.'
            print ''
            Terminate(-1)            
        elif (LG.emailrecp == '<email recipient>'):
            print 'The email recipient has not been configured.  Please edit the pyrecon.conf file before continuing.'
            print ''
            Terminate(-1)
        else:
            AP.emailrecp = LG.emailrecp.rstrip('\n')

        if (len(LG.emailsend) < 4):
            print 'The log directory has not been configured.  Please edit the pyrecon.conf file before continuing.'
            print ''
            Terminate(-1)          
        elif (LG.emailsend == '<email sender>'):
            print 'The email sender has not been configured.  Please edit the recon.conf file before continuing.'
            print ''
            Terminate(-1)
        else:
            AP.emailsend = LG.emailsend.rstrip('\n')        
       
        if (AP.mode == 'auto'):            
            LogProcess()
            IP = LG.data.split()
            for current_IP in IP:
                logdir = AP.logdir + current_IP + '/'
                if (AP.debug == True):
                    print 'logdir: ' + AP.logdir + current_IP
                    print ''
                if not os.path.exists(logdir):
                    os.makedirs(logdir)
                    Whois(current_IP, logdir)
                    NMap(current_IP, logdir)
                    if (AP.supresswget == False): 
                        WGet(current_IP, logdir)
                    if (AP.supressemail == False): 
                        Email(current_IP, logdir)
                else:
                    if (AP.debug == True):
                        print current_IP + ': IP has previously been dealt with'
                    
                AP.whois_output_data = ''
                AP.nmap_output_data = ''
                AP.wget_output_data = ''
                AP.wgetSSL_output_data = ''
                AP.wgetTomcat_output_data = ''
        
        if ((AP.mode == 'manual') or (AP.mode == 'fail2ban')):
            logdir = AP.logdir + AP.target + '/'
            if (AP.debug == True):
                print 'logdir: ' + AP.logdir + AP.target
                print ''            
            if not os.path.exists(logdir):
                os.makedirs(logdir)
                Whois(AP.target, logdir)
                NMap(AP.target, logdir)
                if (AP.supresswget == False):
                    WGet(AP.target, logdir)
                if (AP.supressemail == False):
                    Email(AP.target, logdir)
            else:
                if (AP.debug == True):
                    print AP.target + ': IP has previously been dealt with'

        if ret == 1:
            Terminate(-1)
        else:
            print 'Program Complete'
            Terminate(0)
