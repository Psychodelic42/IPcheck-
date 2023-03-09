# IPcheck

Simple IPcheck from netstat output based on virustotal api v2.

The script expects a text file as input, which should be the output of the command "netstat -ano".
So simply use "netstat -ano >> connections.txt" to generate the file.

Be aware that free accounts at virustotal are limited as follows:

Request rate 	4 lookups / min
Daily quota 	500 lookups / day
Monthly quota 	15.50 K lookups / month 
