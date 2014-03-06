PYRecon v0.4 - Copyright 2014 James Slaughter,
This file is part of PYRecon v0.4.

PYRecon v0.4 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

PYRecon v0.4 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with PYRecon v0.4.  If not, see <http://www.gnu.org/licenses/>.

Usage: [required] --mode [optional] --target --supresswget --supressemail --debug --help
       Required Arguments:
       --mode [auto, manual, fail2ban] - auto to be run as a scripted cron job, manual to be run as a one off and fail2ban to be run with Fail2ban
       Optional Arguments:
       --target[Must be IP to work properly]
       --supresswget - will not attempt a WGET against the target.
       --supressemail - will not send out an e-mail summarizing the actions taken.
       --debug - prints verbose logging to the screen to troubleshoot issues with a recon installation.
       --help - You're looking at it!

CHANGELOG VERSION v0.4:
- Changed logging directory scheme so a subdirectory of the date is created each day letting you track how many times an IP attacks potentially.
- Added a new line in the PyRecon config file to allow WGet to use a browser user-agent string
- Changed the e-mail structure to include the line from auth.log that triggered the event


CHANGELOG VERSION v0.3:
- Merged code from mirage v0.1 for WGet function.  Handles all HTTP/HTTPS ports gathered from NMap instead of just 80/443/8080.
- Removed "elif (line.find('error: connect_to') != -1):" from logreader.py since it didn't work properly.

