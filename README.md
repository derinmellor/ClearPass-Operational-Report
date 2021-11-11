# ClearPass-Operational-Report

#########################################################################
#								                                                      	#
#	      ClearPass Operational Report Configuration File 		            #
#									                                                      #
#			    Version DRAFT 0.05				                                    #
#		             1st December 2020				                              #
#			   derin.mellor@gmail.com			                                    #
#									                                                      #
# This is the configuration file controls how report.exe operates. 	    #
#									                                                      #
#########################################################################

# WARNING: Minimal testing has been done on this code. 
# Please treat with extreme care.

# This has only been tested on ClearPass 6.7-6.9.
# I very much doubt that it will work on 6.10 due to changes in the
# underlying SQL database structure.

To run the program use:
   report.exe [-D] [-d|-w|-m]
Where the options
-D (debug) is available if problems occur.
		This -D is a global setting and generates a lot of logs.
		If you have an issue please use the -D option and send 
		these details with a description of the problem to 
		derin.mellor@gmail.com
-d reports yesterday up to yesterday at 23:59:59
-w reports last week up to yesterday at 23:59:59
-m reports last 4 weeks up to yesterday at 23:59:59
NOTE: If this file's [report] section has the 'start' and 'end' 
 attributes defined these values will be used irrespective of the 
 -d|-w|-m settings.

Running this program will generate two PDFs:
Executive Summary report: This provides a quick overview of the 
ClearPass' operation including:
	ClearPass Cluster Authentication v Time
	Associated Error Events
	Maximum License Usage
	Endpoint Status
	'Possibly' Missing Known Endpoints
	Recommendations
Detailed report with lots more details on the above and more

Use both reports will help identify problems and optimise the ClearPass' 
operation.
If there are any reports that are suboptimal or you require other reports
please email derin.mellor@gmail.com with you requirement and I'll see 
what the effort is to add it in.

WARNING: This is Alpha code with minimal testing. Extreme care should be 
taken when using it. It is not known what the performance implications are 
if this is run on an operational ClearPass appliance. Because of this it 
is recommended to run this on a Test ClearPass appliance or dedication 
Insight appliance. In the case of the Test ClearPass appliance the Insight 
database should be backed up on the Publisher and restored to the Test 
ClearPass appliance.

WARNING: The SQL queries do intensive searching of the Insight database. 
From the limited testing I have done on my very old, and under-resourced, 
ClearPass appliance an Insight database of ~100K authentications per hour
was taking around 8 hours to generate a month long report! This was after 
improving the SQL! Because of this I recommend initially using the yesterday
report to get a feel for the size. This will give you a baseline, on my 
system this take ~20 minutes. Expanding to a week takes a couple of hours.
However, every system is different and I would appreciate feedback. 

Regards Derin 
 
PS I've tried to keep most of the strings in this file so if you want to 
translate or add your own 'comments' it shouldn't be too hard a process.
If you do go down this route please inform me as it might be of interest 
to others.

