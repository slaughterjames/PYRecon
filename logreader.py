'''
PYRecon v0.3 - Copyright 2014 James Slaughter,
This file is part of PYRecon v0.3.

PYRecon v0.3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.


PYRecon v0.3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with PYRecon v0.3.  If not, see <http://www.gnu.org/licenses/>.
'''


'''
logreader.py - This file is responsible for providing a mechanism to read 
the /var/log/auth.log file 
'''


#No python imports
from array import *

#Programmer generated imports
from fileio import fileio

'''
logreader
Class:  This class is responsible for providing a mechanism to read
the /var/log/auth.log file
'''

class logreader:

    '''
    Constructor
    '''
    def __init__(self):
        
        self.logdir = ''
        self.emailrecp = ''
        self.emailsend = ''
        self.filename = '/var/log/auth.log'
        self.confname = '/etc/pyrecon/pyrecon.conf'
        self.data = ''
        self.http_data = array('i')
        self.https_data = array('i')

    '''
    ConfRead()
    Function: - Reads in the pyrecon.conf config file
       
    '''
    def ConfRead(self, debug):
        FConf = fileio()
        FConf.ReadFile(self.confname)
        for line in FConf.fileobject:
            if (debug == True):
                print line
            intLen = len(line)
            if (line.find('logdir') != -1):                
                self.logdir = line[7:intLen]
            elif (line.find('emailrecp') != -1):
                self.emailrecp = line[10:intLen]
            elif (line.find('emailsend') != -1):
                self.emailsend = line[10:intLen]
            else:
                if (debug == True): 
                    print ''
        
        if (debug == True):    
            print 'Finished configuration.'
            print ''


    '''
    NMapRead()
    Function: - Reads in the generated NMap file
              - Looks for two specific items on each line from which to pull information on an http/https port
       
    '''
    def NMapRead(self, filename, debug):
        FLog = fileio()
        FLog.ReadFile(filename)
        tmpport = ''
        self.http_data = array('i')
        self.https_data = array('i')

        for line in FLog.fileobject:
            if (line.find('ssl/http') != -1):
                intFromVal1 = line.find('/')
                if ((intFromVal1 != -1) and (intFromVal1 <7)):
                    tmpport = line[0:intFromVal1]
                    self.https_data.append(int(tmpport))
                    self.http_data.append(int(tmpport))
                    if (debug == True):
                        print 'Port: ' + tmpport
                    else:
                        if (debug == True):
                            print ''
                    
                    tmpport = ''
            else:
                if (line.find('http') != -1):
                    intFromVal1 = line.find('/')
                    if ((intFromVal1 != -1) and (intFromVal1 <7)):
                        tmpport = line[0:intFromVal1]
                        self.http_data.append(int(tmpport))
                        if (debug == True):
                            print 'Port: ' + tmpport
                        else:
                            if (debug == True):
                                print ''                            
                        
                        tmpport = ''

        return 0


            
    '''
    LogRead()
    Function: - Reads in the /var/log/auth.log file
              - Looks for two specific lines from which to pull a suspect IP address
       
    '''
    def LogRead(self, debug):
        FLog = fileio()
        FLog.ReadFile(self.filename)
        for line in FLog.fileobject:
            if (line.find('Bad protocol version identification') != -1):
                intFromVal1 = line.find('from')
                if (intFromVal1 != -1):
                    intLen = len(line)
                    intFromVal2 = intFromVal1 + 5
                    self.data += line[intFromVal2:intLen]
                    if (debug == True):
                        print 'IP: ' + self.data
            elif (line.find('Did not receive identification string') != -1):
                intFromVal1 = line.find('from')
                if (intFromVal1 != -1):
                    intLen = len(line)
                    intFromVal2 = intFromVal1 + 5
                    self.data += line[intFromVal2:intLen]
                    if (debug == True):
                        print 'IP: ' + self.data
            else:
                if (debug == True):
                    print ''                            

        return 0
