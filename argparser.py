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
argparser.py - This file is responsible for the parsing of input data from the command line
               from a user and then populating the appropriate values for use elsewhere in 
               the code
'''

#No python imports

#No programmer imports

'''
argparser
Class: This class is responsible for the parsing of input data from the command line
from a user and then populating the appropriate values for use elsewhere in the code
'''
class argparser:
    '''
    Constructor
    '''
    def __init__(self):

        self.mode = ''
        self.target = ''
        self.supresswget = False
        self.supressemail = False
        self.logdir = ''
        self.emailrecp = ''
        self.emailsend = ''
        self.whois_output_data = ''
        self.nmap_output_data = ''
        self.nmap_filename = ''
        self.wget_output_data = ''
        self.debug = False
        
        
    '''       
    Parse()
    Function: - Determines if all required arguments are present
              - Populates the required variables               
    '''    
    def Parse(self, args):        
        option = ' '
        
        if len(args) < 3:        
            print 'Insufficient number of arguments.'
            print ''
            return -1
         
        print 'Arguments: '
        for i in range(len(args)):
            if args[i].startswith('--'):
                option = args[i][2:]
                
                if option == 'help':
                    return -1

                if option == 'mode':
                    self.mode = args[i+1]
                    print option + ': ' + self.mode

                if option == 'target':
                    self.target = args[i+1] 
                    print option + ': ' + self.target

                if option == 'supresswget':
                    self.supresswget = True
                    print option + ': ' + str(self.supresswget)

                if option == 'supressemail':
                    self.supressemail = True
                    print option + ': ' + str(self.supressemail)

                if option == 'debug':
                    self.debug = True
                    print option + ': ' + str(self.debug)

        print ''                    
       
        if len(self.mode) < 4:
            print 'mode is a required argument'
            print ''
            return -1
        else:
            if (self.mode == 'auto'):
                print 'mode is auto'
                print ''
            elif (self.mode == 'manual'):
                print 'mode is manual'
                print ''
                if len(self.target) < 4:
                    print 'target is a required argument with manual mode'
                    print ''
                    return -1
            elif (self.mode == 'fail2ban'):
                 print 'mode is fail2ban'
                 print ''
                 if len(self.target) < 4:
                     print 'target is a required argument with fail2ban mode'
                     print ''
                     return -1
            else:
                print 'mode must be set to auto, fail2ban or manual'
                print ''
                return -1
            
                                
        return 0
