#!/usr/bin/env python3
#
# The purpose of this code is to interrogate ClearPass using SQL to generate reports
#
import sys
import os
import psycopg2
import numpy as np
from configparser import ConfigParser
from datetime import date
from datetime import datetime, timedelta
from pytz import timezone
import calendar 
import matplotlib.pyplot as plt
import matplotlib.dates as dates
import time
from calendar import timegm
from fpdf import FPDF
import xml.etree.ElementTree as ET
import re
from getpass import getpass
# from secureconfig import SecureCofigParser

EXPIRE='2021-07-28'
VERSION='0.07 DRAFT'
CLUSTER=[]
TODAY=date.today()
END=TODAY.strftime('%Y-%m-%d')
lastMonth = TODAY - timedelta(days=30)
START=lastMonth.strftime('%Y-%m-%d')
IGNORE=''
H=6
h=10
GRAPH_H=140
LAND_W=250
PORT_W=180
REVIEW={}
STALE_PERCENT=5
DEBUG=False
MAX_AUTH=0
ANON_MAC=False
ANON_MAC_DIC={}
ANON_MAC_ON=0
ANON_IP=False
ANON_IP_DIC={}
ANON_IP_NO=0
ANON_USER=False
ANON_USER_DIC={}
ANON_USER_NO=0
ANON_HOST=False
ANON_HOST_DIC={}
ANON_HOST_NO=0
ANON_NAS=False
ANON_NAS_DIC={}
ANON_NAS_NO=0
ANON_CPPM=False
ANON_CPPM_DIC={}
ANON_CPPM_NO=0
ANON_SERVICE=False
ANON_SERVICE_DIC={}
ANON_SERVICE_NO=0
ANON_ALERT_FILTER=''
FILE_INDEX=0

############################################# 
# Parse postgresql details file
def configdb(filename, section):
#     if DEBUG:
#         print('Entering configdb: filename=', filename, ' section=', section)
     parser = ConfigParser()
     parser.read(filename)
     db={}
     if parser.has_section(section):
          params = parser.items(section)
          for param in params:
               db[param[0]] = param[1]
     else:
          raise Exception('Section {0} not found in the {1}'.format(section, filename))
#     if DEBUG:
#         print('Leaving configdb: db=', db)
     return db


############################################# 
# Connect to ClearPass SQL database
def connect():

    if DEBUG:
        print('Entering connect')
    times=[]
    values=[]
    conn = None
    try:
        params = configdb('report.ini', 'postgresql')

        if 'host' not in params:
            print('Please enter ClearPass\' Insight database hostname/IP: ',end='')
            params['host'] = input()

        if DEBUG:
            print('params=', params)


            # If password not predefined ask user to input
        if 'password' not in params:
#            print('Please enter the appexternal\'s password: ', end='')
            #params['password'] = input()
            params['password'] = getpass(prompt='Please enter appexternal password: ')
     
                # connect to the PostgreSQL server
        conn = psycopg2.connect(**params)
    except OperationalError as err: 
        print(err)
        sys.exit("Failed to connect to database")
    finally:
        if DEBUG:
           print('Leaving connect: conn=', conn)
        return conn          


############################################# 
# Create list of success/failed auths per hour graph
def cluster_auths(conn, pdf):

     global MAX_AUTH 
     global FILE_INDEX

     if DEBUG:
         print('Entering cluster_auths')
     cur=conn.cursor()
     times=[]
     successes=[]
     failures=[]
     MAX_AUTH=0

     try:
          section = configdb('report.ini', 'ClearPass Cluster Authentications per hour')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
     # execute a statement

          f=plt.figure()
          plt.title(heading)
          plt.ylabel('authentications')
          plt.xlabel('date')
          plt.xticks(rotation=90)
          plt.grid(True)

          cmd = "SELECT Auth_hour, COUNT(error_code) FILTER (WHERE error_code = 0) AS Success, COUNT(error_code) FILTER (WHERE error_code !=0) AS Failed FROM (SELECT date_trunc('hour', auth.timestamp) AS Auth_hour, error_code FROM auth JOIN cppm_cluster ON auth.cppm_uuid=cppm_cluster.uuid WHERE timestamp >= '{}' AND timestamp < '{}' AND cppm_cluster.management_ip != '{}') tmp GROUP BY Auth_hour ORDER BY Auth_hour ASC".format(START, END, IGNORE)
#          print(cmd)
          cur.execute(cmd)

               # get start time
          t=datetime.strptime(START, '%Y-%m-%d')
               # add timezone
               # as return from SQL includes timezone
          expect_time = t.replace(tzinfo=timezone('UTC'))
          row = cur.fetchone()
          while row is not None:
#               if DEBUG:
#                   print('Row=',row)
               timestamp = row[0]
               success = int(row[1])
               failed = int(row[2])

                    # Record the max_auth
               if success+failed>MAX_AUTH:
                   MAX_AUTH=success+failed

#               print('Timestamp', timestamp, 'Success', success, 'Failed', failed, 'Expect_time', expect_time
                    # Fill in any missing gaps
               while timestamp > expect_time:
                    if DEBUG:
                        print('missing @', expect_time, 'got', timestamp)
                    times.append(expect_time)
                    successes.append(0)
                    failures.append(0)
                    expect_time = expect_time + timedelta(hours=1)
               expect_time = expect_time + timedelta(hours=1)
               times.append(timestamp)
               successes.append(success)
               failures.append(failed)
               row = cur.fetchone()

          plt.plot(times, successes, 'g-')
          plt.plot(times, failures, 'r-')
#          plt.stackplot(times, successes, 'g-')
#          plt.stackplot(times, failures, 'r-')

#          plt.show()
          FILE_INDEX+=1
          filename='graph'+str(FILE_INDEX)
          plt.savefig(filename, format='png', bbox_inches='tight')
          plt.close()

          pdf.image(filename, w=PORT_W, h=GRAPH_H, type='PNG')
          if os.path.exists(filename):
               os.remove(filename)

          pdf.set_font("Arial", size = 11)
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
     if DEBUG:
          print('Leaving cluster_auths')


############################################## 
# Create list of success/failed auths per hour per ClearPass graph
def cluster_load_distribution(conn, pdf):

    global ANON_CPPM
    global ANON_CPPM_DIC
    global ANON_CPPM_NO
    global FILE_INDEX

    cppm={}
    stamps=[]
    cp_auths=[]

    if DEBUG:
        print('Entering cluster_load_distribution')
    cur=conn.cursor()

    try:
        section = configdb('report.ini', 'ClearPass Cluster Details')
        heading1=section['title']     
        print('\t'+heading1+' (timestamp='+str(datetime.now().time())+')')
        comment1=section['comment']

        section = configdb('report.ini', 'ClearPass Cluster Authentication Load Distribution')
        heading2=section['title']     
        print('\t'+heading2+' (timestamp='+str(datetime.now().time())+')')
        comment2=section['comment']
        pdf.set_font("Arial", 'B', size = 16)
        pdf.cell(0, h, heading2, 0, 1, 'L')

            # execute a statement
        plt.title(heading2)
        plt.ylabel('authentications')
        plt.xlabel('time')
        plt.xticks(rotation=90)
        plt.grid(True)

            # set up time with timezone
        t=datetime.strptime(START, '%Y-%m-%d')
        start_time = t.replace(tzinfo=timezone('UTC'))
        t=datetime.strptime(END, '%Y-%m-%d')
        end_time = t.replace(tzinfo=timezone('UTC'))

                # Setup the timestamps in stamps
        t = start_time
        while t < end_time:
            stamps.append(t)
            t = t + timedelta(hours=1)
        stamps=np.array(stamps)
        end_index=len(stamps)-1

        if DEBUG:
            print('Stamps=',stamps, 'end_index=',end_index)
            
        cmd="SELECT hostname, uuid, Auth_hour, COUNT(*) AS Auths FROM (SELECT cppm_cluster.hostname, uuid, date_trunc('hour', auth.timestamp) AS Auth_hour, error_code FROM auth JOIN cppm_cluster ON auth.cppm_uuid=cppm_cluster.uuid WHERE timestamp >= '{}' AND timestamp < '{}' AND cppm_cluster.management_ip != '{}') tmp GROUP BY hostname, uuid, Auth_hour ORDER BY hostname, Auth_hour ASC".format(START, END, IGNORE)
#        print(cmd)
        cur.execute(cmd)

        row = cur.fetchone()

        if row is None:     # Hmm no authentications! Are the dates right?
            return False

            # row[0] = clearpass
            # row[1] = uuid
            # row[2] = timestamp
            # row[3] = auth count

            # First get all the ClearPass & their UUID
        time_index=0
        cp_index=-1
        uuid=''
        while row is not None:
#            if DEBUG:
#                print('Row=',row)
            if row[1]!=uuid:    # Must be another appliance

                    # First time appliance cp_index=-1
                if cp_index>=0:
                        # Fill-in any missing end entries on previous ClearPass
                    while time_index<=end_index:
                        cp_auths.append(0)
                        time_index+=1
                        print('End missing1 @ Expect time index: ',end_index, ', Got: ', time_index, ', Append 0')

                           # Record the previous ClearPass
#                    print('Plot ', hostname, ' auth: ', cp_auths)
                    x, =plt.plot(stamps, cp_auths, label=hostname)
                    x.set_label(hostname)
                    del cp_auths[:]    # clear array

                        # Record new ClearPass appliance
                if ANON_CPPM:
                    hostname,ANON_CPPM_NO=get_anonymous_name(row[0], ANON_CPPM_DIC, ANON_CPPM_NO, 'AnonCPPM')
                else:
                    hostname=row[0]
                print('\t\tActive appliance ', hostname)
                cppm['Hostname']=hostname
                cppm['UUID']=row[1]
#                print('cppm=',cppm)
                CLUSTER.append(dict(cppm))
                cp_index+=1
                time_index = 0
                uuid=row[1]
#                print('CLUSTER=',CLUSTER, 'ClearPass=',hostname, 'cp_index=',cp_index)

                # If missing time entry (ie no auths) fill-in gaps
            while stamps[time_index]<row[2]:
                cp_auths.append(0)
                if DEBUG: 
                    print('missing entry @ time_index=', time_index, 'Expect timestamp: ',row[2], ', Got: ', stamps[time_index], ', Append 0')
                time_index+=1

                # Record value
            if stamps[time_index]==row[2]: 
                cp_auths.append(row[3])
#                print('append auths=',row[3])
                time_index+=1
            else:
                print('How did I get here? stamps[time_index]=',stamps[time_index],', row[2]=',row[2])

                # Get next entry
#            print('Get next row')
            row = cur.fetchone()

            # Sort out the last ClearPass
                # Fill-in missing end entries
        while time_index<=end_index:
            cp_auths.append(0)
            if DEBUG:
                print('End missing @ Expect time index: ',end_index, ', Got: ', time_index, ', Append 0')
            time_index+=1
#        print('Final CLUSTER=',CLUSTER, 'ClearPass=',hostname, 'cp_index=',cp_index)
#        print('Plot ', name, ' auth: ', cp_auths)
        if len(stamps)!=len(cp_auths):
            print('Error!!! length stamp=',len(stamps),', and length cp_auths=',len(cp_auths))
        x, =plt.plot(stamps, cp_auths, label=hostname)
        x.set_label(hostname)

        plt.legend()
#        plt.show()
        FILE_INDEX+=1
        filename='graph'+str(FILE_INDEX)
        plt.savefig(filename, format='png', bbox_inches='tight')
        plt.close()

        pdf.image(filename, w=LAND_W, h=GRAPH_H, type='PNG')
        if os.path.exists(filename):
            os.remove(filename)

        pdf.set_font("Arial", size = 11)
        pdf.multi_cell(0, H, comment2, 0, 'L', False)
          
        pdf.ln(h)
                # Print all the ClearPass details
        pdf.set_font("Arial", 'B', size = 16)
        pdf.cell(0, h, heading1, 0, 1, 'L')
        pdf.set_font("Arial", 'B', size = 11)
        pdf.cell(0, h, comment1, 0, 1, 'L')
        pdf.cell(15, h, '', 0, 0, 'L')
        pdf.cell(75, h, "ClearPass", 0, 0, 'L')
        pdf.cell(75, h, "IP", 0, 0, 'L')
        pdf.cell(75, h, "Zone", 0, 1, 'L')
        pdf.set_font("Arial", size = 11)

        string=''
        for clearpass in CLUSTER:

            if string=='':
                string='\''+clearpass['UUID']+'\''
            else:
                string+=',\''+clearpass['UUID']+'\''

        cmd="SELECT is_publisher, management_ip, hostname, zone FROM cppm_cluster WHERE uuid IN ({}) ORDER BY hostname".format(string)
#        print(cmd)
        cur.execute(cmd)

        row = cur.fetchone()
            # row[0]    is_publisher
            # row[1]    management_ip
            # row[2]    hostname
            # row[3]    zone
        while row is not None:
            if DEBUG:
                print('Row=',row)
            hostname=row[2]
            publisher=row[0]
            ip=row[1]
            zone=row[3]
            if ANON_CPPM:
                hostname=ANON_CPPM_DIC[hostname]
                ip='XXXXXXXXXXXX'
                zone='ZZZZZ'
            elif publisher is True:
                hostname += ' (Publisher)'     
            pdf.cell(15, H, '', 0, 0, 'L')
            pdf.cell(75, H, hostname, 0, 0, 'L')
            pdf.cell(75, H, ip, 0, 0, 'L')
            pdf.cell(75, H, zone, 0, 1, 'L')

#            print('Hostname=',hostname,', ip=',ip,', zone=',zone)
            row = cur.fetchone()
            
        pdf.ln(2*h)
        if DEBUG:
            print('Leaving cluster_load_distribution')
        return True

    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return False

    except error:
        print(error)
        return False

############################################# 
# Create list of max license usage table
def max_license(conn, pdf):

     if DEBUG:
         print('Entering max_license')
     cur = conn.cursor()
     times=[]
     values=[]
     try:
          section = configdb('report.ini', 'Maximum License Usage')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
     # execute a statement
          cmd = "SELECT MAX(used_count) FILTER (WHERE app_name = 'Entry') AS Top_Entry_License_Usage, MAX(total_count) FILTER (WHERE app_name = 'Entry') AS Top_Entry_License, MAX(used_count) FILTER (WHERE app_name = 'Access') AS Top_Access_License_Usage, MAX(total_count) FILTER (WHERE app_name = 'Access') AS Top_Access_License, MAX(used_count) FILTER (WHERE app_name = 'Onboard') AS Top_Onboard_License_Usage, MAX(total_count) FILTER (WHERE app_name = 'Onboard') AS Top_Onboard_License, MAX(used_count) FILTER (WHERE app_name = 'OnGuard') AS Top_OnGuard_License_Usage, MAX(total_count) FILTER (WHERE app_name = 'OnGuard') AS Top_OnGuard_License FROM cppm_license WHERE node_ip != '{}' AND timestamp >= '{}' AND timestamp <= '{}'".format(IGNORE, START, END)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()

               # row[0] Entry max usage
               # row[1] Entry max license
               # row[2] Access max usage
               # row[3] Access max license
               # row[4] Onboard max usage
               # row[5] Onboard max license
               # row[6] OnGuard max usage
               # row[7] OnGuard max license
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(10, h, "", 0, 0, 'L')
          if row[1] is None:
               pdf.cell(40, h, "Entry (0)", 0, 0, 'C')
          else:
               value="Entry ("+str(row[1])+")"
               pdf.cell(40, h, value, 0, 0, 'C')
          value="Access ("+str(row[3])+")"
          pdf.cell(40, h, value, 0, 0, 'C')
          value="Onboard ("+str(row[5])+")"
          pdf.cell(40, h, value, 0, 0, 'C')
          value="OnGuard ("+str(row[7])+")"
          pdf.cell(40, h, value, 0, 1, 'C')

          pdf.set_font("Arial", size = 11)
          pdf.cell(10, H, "", 0, 0, 'C')
          if row[0] is None:
               pdf.cell(40, H, "0", 0, 0, 'C')
          else:
               pdf.cell(40, H, str(row[0]), 0, 0, 'C', fill=set_background(pdf,row[0],row[1]))
          pdf.cell(35, H, str(row[2]), 0, 0, 'C', fill=set_background(pdf,row[2],row[3]))
          pdf.cell(5, H, "", 0, 0, 'L')
          pdf.cell(35, H, str(row[4]), 0, 0, 'C', fill=set_background(pdf,row[4],row[5]))
          pdf.cell(5, H, "", 0, 0, 'L')
          pdf.cell(35, H, str(row[6]), 0, 0, 'C', fill=set_background(pdf,row[6],row[7]))

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          if DEBUG:
              print('Leaving max_license')
          pdf.ln(2*h)


def set_background(pdf, value, limit):

#     print('Entering set_background: value=',value,', limit=',limit)
     REVIEW['max_license']=''
     if limit == 0:
          return False
     if value > limit:
               # set background colour red
          pdf.set_fill_color(255,0,0)
          REVIEW['max_license']='High'
          return True
     elif (value*100)/limit > 90:
               # set background colour amber
          pdf.set_fill_color(255,194,0)
          if REVIEW['max_license']!='High':
               REVIEW['max_license']='Med'
          return True
     elif value*2 < limit: 
               # set background colour green
          pdf.set_fill_color(50,205,50)
          REVIEW['max_license']='High'
          return True
     else:
          pdf.set_fill_color(255,255,255)
          return False


############################################# 
# Create license usage graph
def license(conn, pdf):

     global FILE_INDEX

     if DEBUG:
         print('Entering license')
     cur = conn.cursor()
     times=[]
     values=[]
     stale=[]
     dat=[]
     try:
          section = configdb('report.ini', 'Access License Usage over Time')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          
     # execute a statement
          plt.title(heading)
          plt.ylabel('license usage')
          plt.xlabel('date')
          plt.xticks(rotation=90)
          plt.grid(True)

          cmd = "SELECT node_ip, timestamp, used_count, total_count FROM cppm_license WHERE node_ip != '{}' AND app_name ='Access' AND timestamp >= '{}' AND timestamp <= '{}' ORDER BY timestamp ASC".format(IGNORE,START,END)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()

               # row[0] node_id
               # row[1] timestamp
               # row[2] user_count
               # row[3] total_count

               # Set line on graph showing max license 
               # Counts from midnight=0 in 15 min steps
          quarter=0
          before=0
          first=True
          while row is not None:
#               if DEBUG:
#                   print('Row=',row)
               timestamp = row[1]
               times.append(timestamp)
               result = int(row[2])
               values.append(result)

                    # Monitor licenses recovered from stale endpoints
                    # record value at 23:45
               if first == True: 
                    if quarter == 95:
                         first = False
               if quarter == 95:
                    before=result
                    if before==0:
                        print('WARNING: Stale License - Did not expect 0 license count!')
                    # record value at 00:45
               elif quarter == 3:
                         # first one ignore
                    if first != True:
                              # Calculate % change
                         if before>0:
                             ans=round(((before-result)*100)/before,0)
                             if ans > STALE_PERCENT:     # If above 5% then record
                                 stale.append(ans)
                                 dat.append(timestamp)
               quarter+=1
               if quarter == 96:
                    quarter=0
               row = cur.fetchone()

#          plt.axhline(row[3],xmin=0, xmax=1)
          plt.plot(times, values, 'b-')
#          plt.show()
          FILE_INDEX+=1
          filename='graph'+str(FILE_INDEX)
          plt.savefig(filename, format='png', bbox_inches='tight')
          plt.close()

          pdf.image(filename, w=LAND_W, h=GRAPH_H, type='PNG')
          if os.path.exists(filename):
               os.remove(filename)

          pdf.set_font("Arial", size = 11)
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          pdf.ln(h)
          
          section = configdb('report.ini', 'Stale Access License Recovery')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          i = len(stale)
          if i >= 1:
                    # Only print the first 10
               if i > 10:
                    i=10
               pdf.set_font("Arial", 'B', size = 16)
               if i>10:
                    label='First 10 of '+str(i)+' Stale Licenses Recovered > %', str(STALE_PERCENT), ' of existing sessions'
               elif i==1:
                    label='Only Stale License Recovered > ', str(STALE_PERCENT),'% of existing sessions'
               else:
                    label='First of '+str(i)+' Stale Licenses Recovered > ', str(STALE_PERCENT), '% of existing sessions'
               pdf.cell(0, h, label, 0, 1, 'L')
               pdf.set_fill_color(255,194,0)
               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(30, h, "Date", 0, 0, 'C')
               pdf.cell(30, h, "%", 0, 1, 'C')

               pdf.set_font("Arial", size = 11)
               j=0
               while j < i:
                    stamp = dat[j]
                    pdf.cell(30, H, stamp.strftime("%d-%m-%y"), 0, 0, 'C', fill=True)
                    pdf.cell(30, H, str(stale[j]), 0, 1, 'C', fill=True)
                    j+=1
          else: 
               pdf.set_font("Arial", size = 11)
               pdf.cell(0, H, 'Nothing exceptional', 0, 1, 'L')
               

#          plt.plot(dat, stale, 'b-')
##          plt.show()
#          plt.savefig('tmp4.png', format='png', bbox_inches='tight')
#          plt.close()
#
#          pdf.image('tmp4.png', w=LAND_W, h=GRAPH_H, type='PNG')
#          if os.path.exists('tmp4.png'):
#               os.remove('tmp4.png')

          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          if DEBUG:
              print('Leaving license')
          pdf.ln(h)


############################################# 
# Endpoint Device Status
def endpoint_status(conn, pdf):

     global MAX_AUTH 

     if DEBUG:
         print('Entering endpoint_status, MAX_AUTH=',MAX_AUTH)
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Endpoint Status')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          comment2=section['comment2']     
          comment3=section['comment3']     
          comment4=section['comment4']     
          comment5=section['comment5']     
          comment6=section['comment6']     
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          
          cmd = "SELECT COUNT(mac) AS Total, COUNT(mac) FILTER (WHERE status = 'Disabled') AS Disabled, COUNT(mac) FILTER (WHERE status = 'Known') AS Known, COUNT(mac) FILTER (WHERE status IS NULL OR status = 'Unknown') AS Unknown FROM endpoints WHERE updated_at >= '{}' AND updated_at < '{}'".format(START,END)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()
               # row[0] total
               # row[1] disabled
               # row[2] known
               # row[3] unknown
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "Total", 0, 0, 'C')
          pdf.cell(30, h, "Disabled", 0, 0, 'C', )
          pdf.cell(30, h, "Known", 0, 0, 'C')
          pdf.cell(30, h, "Unknown", 0, 1, 'C')

          pdf.set_font("Arial", size = 11)
          pdf.cell(30, H, str(row[0]), 0, 0, 'C')
          
          pdf.set_fill_color(255,255,255)
          if row[1] > 0:
               alert=True
               pdf.set_fill_color(255,0,0)
               REVIEW['endpoints_missing']='High'
          else:
               alert=False
          pdf.cell(30, H, str(row[1]), 0, 0, 'C', fill=alert)
          pdf.cell(30, H, str(row[2]), 0, 0, 'C')
          if row[3] > 0:
               alert=True
               pdf.set_fill_color(255,194,0)
               REVIEW['endpoints_missing']='Med'
          else:
               alert=False
          pdf.cell(30, H, str(row[3]), 0, 1, 'C', fill=alert)

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
          pdf.ln('')
          pdf.multi_cell(0, H, comment2, 0, 'L', False)
          alert=False
          comment=''
          if MAX_AUTH>(row[0]*4):
               pdf.set_fill_color(255,0,0)
               comment=comment3+str(MAX_AUTH)+comment4
               pdf.multi_cell(0, H, comment, 0, 'L', True)
          elif MAX_AUTH>(row[0]*2):
               pdf.set_fill_color(255,194,0)
               comment=comment5+str(MAX_AUTH)+comment6
               pdf.multi_cell(0, H, comment, 0, 'L', True)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          if DEBUG:
              print('Leaving endpoint_status')
          pdf.ln(2*h)


############################################# 
# Endpoint IP assignment
def endpoint_IP_assign(conn, pdf):

     if DEBUG:
         print('Entering endpoint_IP_assign')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Endpoint IP Address Assignment')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd = "SELECT COUNT(mac) AS Total, COUNT(mac) FILTER (WHERE static_ip IS True) AS StaticIP, COUNT(mac) FILTER (WHERE static_ip IS False) AS DHCP FROM endpoints WHERE updated_at >= '{}' AND updated_at < '{}'".format(START,END)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()
               # row[0] total
               # row[1] Static_IP
               # row[2] DHCP_Address
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "Total", 0, 0, 'C')
          pdf.cell(30, h, "Static IP", 0, 0, 'C', )
          pdf.cell(30, h, "DHCP Address", 0, 1, 'C')

          pdf.set_font("Arial", size = 11)
          pdf.cell(30, H, str(row[0]), 0, 0, 'C')
               # If more static the DHCP - amber
          pdf.set_fill_color(255,255,255)
          alert=False
          if row[0] > 0:
            if row[1] > row[2]:
                    alert=True
                    pdf.set_fill_color(255,194,0)
                    REVIEW['endpoint_IP_assign']='Med'
                        # If static more than 75% - red
            elif (row[1]*100)/row[0] > 75:
                    alert=True
                    Pdf.set_fill_color(255,0,0)
                    REVIEW['endpoint_IP_assign']='High'
          pdf.cell(30, H, str(row[1]), 0, 0, 'C', fill=alert)
          pdf.cell(30, H, str(row[2]), 0, 1, 'C')

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          if DEBUG:
              print('Leaving endpoint_IP_assign')
          pdf.ln(2*h)


############################################# 
# Endpoint Address Schema
def endpoint_addr_schema(conn, pdf):

     if DEBUG:
         print('Entering endpoint_addr_schema')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Endpoint MAC & IP Address Details')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd = "SELECT COUNT(mac) AS Total, COUNT(mac) FILTER (WHERE mac NOT LIKE 'x%' AND ip IS NULL) AS MAC_Only, COUNT(mac) FILTER (WHERE mac NOT LIKE 'x%' AND ip IS NOT NULL) AS MAC_and_IP, COUNT(mac) FILTER (WHERE mac LIKE 'x%' AND ip IS NOT NULL) AS IP_Only, COUNT(mac) FILTER (WHERE mac LIKE 'x%' AND ip IS NULL) AS No_MAC_or_IP FROM endpoints WHERE updated_at >= '{}' AND updated_at < '{}'".format(START,END)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()
               # row[0] total
               # row[1] MAC Only
               # row[2] MAC & IP
               # row[3] IP Only
               # row[4] No MAC or IP!
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "Total", 0, 0, 'C')
          pdf.cell(30, h, "MAC Only", 0, 0, 'C', )
          pdf.cell(30, h, "MAC & IP", 0, 0, 'C')
          if row[4] > 0:
               pdf.cell(30, h, "IP Only", 0, 0, 'C')
               pdf.cell(30, h, "No MAC or IP!", 0, 1, 'C')
          else:
               pdf.cell(30, h, "IP Only", 0, 1, 'C')

          pdf.set_font("Arial", size = 11)
          pdf.cell(30, H, str(row[0]), 0, 0, 'C')
          pdf.set_fill_color(255,194,0)
          if row[1] > 0:
               pdf.cell(30, H, str(row[1]), 0, 0, 'C', fill=True)
               REVIEW['endpoints_addr_schema']='Med'
          else:
               pdf.cell(30, H, str(row[1]), 0, 0, 'C')
          pdf.cell(30, H, str(row[2]), 0, 0, 'C')
          pdf.set_fill_color(255,0,0)
          if row[4] > 0:
               pdf.cell(30, H, str(row[3]), 0, 0, 'C', fill=True)
               pdf.cell(30, H, str(row[4]), 0, 1, 'C', fill=True)
               REVIEW['endpoints_addr_schema']='High'
          else:
               pdf.cell(30, H, str(row[3]), 0, 1, 'C', fill=True)
               REVIEW['endpoints_addr_schema']='Med'

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          if DEBUG:
              print('Leaving endpoint_addr_schema')
          pdf.ln(2*h)


############################################# 
# Endpoints with Randomized MAC addresses
def endpoint_random(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_IP
     global ANON_IP_NO
     global ANON_IP_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_HOST
     global ANON_HOST_NO
     global ANON_HOST_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC

     if DEBUG:
         print('Entering endpoint_random')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Endpoints with Randomized MAC Addresses')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd = "SELECT COUNT(mac) FROM endpoints WHERE (mac LIKE '_2%' OR mac LIKE '_6%' OR mac LIKE '_a%' OR mac LIKE '_e%') AND mac NOT LIKE 'x%' AND updated_at >= '{}' AND updated_at < '{}'".format(START,END)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()
               # row[0] count of devices
          pdf.set_font("Arial", size = 11)
          pdf.cell(30, h, "Total", 0, 0, 'C')
          pdf.cell(30, h, str(row[0]), 0, 1, 'C')

          if row[0] > 1:
              cmd = "SELECT mac, COALESCE(ip,''), static_ip, COALESCE(hostname,''), COALESCE(username, ''), nad_ip, nas_port_type, COALESCE(nad_port, ''), ssid, COALESCE(device_category, ''), COALESCE(device_family, ''), COALESCE(device_name, '') FROM endpoints WHERE (mac LIKE '_2%' OR mac LIKE '_6%' OR mac LIKE '_a%' OR mac LIKE '_e%') AND mac NOT LIKE 'x%' AND updated_at >= '{}' AND updated_at < '{}' LIMIT 10".format(START,END)
                                # row[0] = MAC
                                # row[1] = IP
                                # row[2] = StaticIP
                                # row[3] = Hostname
                                # row[4] = Username
                                # row[5] = NAS_IP
                                # row[6] = Media
                                # row[7] = Port
                                # row[8] = SSID
                                # row[9] = Category
                                # row[10] = Family
                                # row[11] = DevType
#               print(cmd)
              cur.execute(cmd)

              pdf.ln(h*2)
              pdf.set_font("Arial", 'B', size = 12)
              pdf.cell(0, h, "10 Last seen Endpoints with Randomized MAC addresses", 0, 1, 'L')
              pdf.set_font("Arial", 'B', size = 11)
              pdf.cell(30, h, "MAC Address", 0, 0, 'L')
              pdf.cell(30, h, "IP Address", 0, 0, 'L')
#               pdf.cell(30, h, "Static IP", 0, 0, 'L')
              pdf.cell(40, h, "Hostname", 0, 0, 'L')
              pdf.cell(50, h, "Username", 0, 0, 'L')
#              pdf.cell(30, h, "NAS IP", 0, 0, 'L')
              pdf.cell(30, h, "Media", 0, 0, 'L')
#              pdf.cell(30, h, "Port", 0, 0, 'L')
#              pdf.cell(30, h, "SSID", 0, 0, 'L')
              pdf.cell(30, h, "Category", 0, 0, 'L')
              pdf.cell(30, h, "Family", 0, 0, 'L')
              pdf.cell(30, h, "DevType", 0, 1, 'L')

              pdf.set_font("Arial", size = 11)
              row = cur.fetchone()
              while row is not None:
                   if DEBUG:
                       print('Row=',row)
                   if ANON_MAC:
                       name,ANON_MAC_NO=get_anonymous_name(row[0], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
                   else:
                       name=row[0]
                   pdf.cell(30, H, name, 0, 0, 'L')
                   if row[1]=='':
                       name=''
                   elif ANON_IP:
                       name,ANON_IP_NO=get_anonymous_name(row[1], ANON_IP_DIC, ANON_IP_NO, 'AnonIP')
                   else:
                       name=row[1]
                   pdf.cell(30, H, name, 0, 0, 'L')
#                   pdf.cell(30, H, row[2], 0, 0, 'L')
                   if row[3]=='':
                       name=''
                   elif ANON_HOST:
                       name,ANON_HOST_NO=get_anonymous_name(row[3], ANON_HOST_DIC, ANON_HOST_NO, 'AnonHost')
                   else:   
                       name=row[3]
                   pdf.cell(40, H, name, 0, 0, 'L')
                   value=normalize_mac(row[4])
                   if row[4]=='':
                       name=''
                   elif value!='' and value==row[0]:     # MAC Auth
                       name=''
                   elif ANON_USER:
                       name,ANON_USER_NO=get_anonymous_name(row[4], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
                   else:   
                       name=row[4]
                   pdf.cell(50, H, name, 0, 0, 'L')
#                   pdf.cell(30, H, row[5], 0, 0, 'L')
                   if row[6] == 15: #Ethernet
                        pdf.cell(30, H, "Wired", 0, 0, 'L')
                   elif row[6] == 19: #Wireless
                        pdf.cell(30, H, "Wifi", 0, 0, 'L')
                   else:          # Not sure? 
                        pdf.cell(30, H, str(row[6]), 0, 0, 'L')
#                   pdf.cell(30, H, row[7], 0, 0, 'L')
#                   pdf.cell(30, H, row[8], 0, 0, 'L')
                   pdf.cell(30, H, row[9], 0, 0, 'L')
                   pdf.cell(30, H, row[10], 0, 0, 'L')
                   pdf.cell(30, H, row[11], 0, 1, 'L')
                   row = cur.fetchone()

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          if DEBUG:
              print('Leaving endpoint_random')
          pdf.ln(2*h)


############################################# 
# Number of Known Endpoints that have not been seen during the period
def endpoints_missing(conn, pdf):

     if DEBUG:
        print('Entering endpoints_missing')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Missing Known Endpoints')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          red_threshold=int(section['threshold'])
          amber_threshold=red_threshold//10

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd = "SELECT COUNT(mac) AS Total, COUNT(mac) FILTER (WHERE status= 'Known') AS Known FROM endpoints WHERE updated_at < '{}'".format(START)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()
        
               # row[0] count of devices
          pdf.set_font("Arial", size = 11)
          pdf.cell(30, h, "Missing", 0, 0, 'C')

          if row[0] > red_threshold:
               pdf.set_fill_color(255,0,0)
               REVIEW['endpoints_missing']='High'
          elif row[0] > amber_threshold:
               pdf.set_fill_color(255,194,0)
               REVIEW['endpoints_missing']='Med'
          else:
               pdf.set_fill_color(255,255,255)
          pdf.set_font("Arial", size = 11)
          pdf.cell(30, h, str(row[0]), 0, 1, 'C', fill=True)

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
            print('Leaving endpoints_missing')


############################################# 
# Known Endpoints that have not been seen during the period
def endpoints_missing_details(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_IP
     global ANON_IP_NO
     global ANON_IP_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_HOST
     global ANON_HOST_NO
     global ANON_HOST_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC

     if DEBUG:
         print('Entering endpoints_missing_details, ANON_MAC=', ANON_MAC)
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Missing Known Endpoints')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     

          cmd = "SELECT COUNT(mac) AS Total, COUNT(mac) FILTER (WHERE status= 'Known') AS Known FROM endpoints WHERE updated_at < '{}'".format(START)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()
               # row[0] count of devices

          if row[0] > 0:
               pdf.set_font("Arial", 'B', size = 12)
               pdf.cell(0, h, heading, 0, 1, 'L')

               pdf.set_fill_color(255,0,0)
               pdf.cell(30, h, str(row[0]), 0, 1, 'C', fill=True)
               cmd = "SELECT updated_at, mac, COALESCE(endpoints.ip,''), COALESCE(hostname,''), COALESCE(username,''), nads.name, COALESCE(nad_ip,''), COALESCE(nas_port_type,''), COALESCE(nad_port,'') AS Port, COALESCE(ssid,'') AS SSID, COALESCE(device_category,''), COALESCE(device_family,''), COALESCE(device_name,'') FROM endpoints JOIN nads ON endpoints.nad_ip = nads.ip WHERE updated_at < '{}' ORDER BY updated_at DESC LIMIT 10".format(START)
#               print(cmd)
               cur.execute(cmd)

               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(25, h, "Last Seen", 0, 0, 'L')
               pdf.cell(30, h, "MAC Address", 0, 0, 'L')
               pdf.cell(40, h, "IP Address", 0, 0, 'L')
               pdf.cell(40, h, "Hostname", 0, 0, 'L')
               pdf.cell(50, h, "Username", 0, 0, 'L')
               pdf.cell(30, h, "NAS Name", 0, 0, 'L')
               pdf.cell(30, h, "NAS IP", 0, 0, 'L')
               pdf.cell(15, h, "Media", 0, 0, 'L')
               pdf.cell(30, h, "Port/SSID", 0, 1, 'L')
#               pdf.cell(30, h, "Category", 0, 0, 'L')
#               pdf.cell(30, h, "Family", 0, 0, 'L')
#               pdf.cell(30, h, "DevType", 0, 1, 'L')
                        
               pdf.set_font("Arial", size = 11)
               row = cur.fetchone()
               while row is not None:
#               while row:
                    if DEBUG:
                        print('Row=',row)
                    pdf.set_fill_color(255,255,255)
                    value = row[0].strftime("%Y/%m/%d")
                    pdf.cell(25, H, value, 0, 0, 'L')
                    if ANON_MAC:
                        name,ANON_MAC_NO=get_anonymous_name(row[1], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
                    else:
                        name=row[1]
                    pdf.cell(30, H, name, 0, 0, 'L', fill=True)
                    if row[2]=='':
                        name=row[2]
                    elif ANON_IP:
                        name,ANON_IP_NO=get_anonymous_name(row[2], ANON_IP_DIC, ANON_IP_NO, 'AnonIP')
                    else:
                        name=row[2]
                    pdf.cell(40, H, name, 0, 0, 'L', fill=True)
                    if row[3]=='':
                        name=row[3]
                    elif ANON_HOST:
                        name,ANON_HOST_NO=get_anonymous_name(row[3], ANON_HOST_DIC, ANON_HOST_NO, 'AnonHost')
                    else:   
                        name=row[3]
                    pdf.cell(40, H, name, 0, 0, 'L', fill=True)
                    value=normalize_mac(row[4])
                    if row[4] == '':        # IF MAC=exists and Username='' THEN MAC Auth
                        name=''
                    elif row[1]==value:     # IF MAC=Username THEN MAC Auth
                        name=''
                    elif ANON_USER:
                        name,ANON_USER_NO=get_anonymous_name(row[4], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
                    else:   
                        name=row[4]
                    pdf.cell(50, H, name, 0, 0, 'L', fill=True)
                    if ANON_NAS:
                                # Often the Hostname is null - use the IP
                        name,ANON_NAS_NO=get_anonymous_name(row[6], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                        name2=name
                    else: 
                        name=row[5]
                        name2=row[6]
                    pdf.cell(30, H, name, 0, 0, 'L', fill=True)
                    pdf.cell(30, H, name2, 0, 0, 'L', fill=True)
                    if row[7] == '5': 
                         media = 'Virtual'
                         value = ""
                    elif row[7] == '15': 
                         media = 'Wired'
                         value = row[8]
                    elif row[7] == '19': 
                         media = 'Wifi'
                         value = row[9]
                    else:          # Not sure? 
                         media = row[7]
                         value = "Null!"
                         pdf.set_fill_color(255,0,0)
                    pdf.cell(15, H, media, 0, 0, 'L', fill=True)
                    pdf.cell(30, H, value, 0, 1, 'L', fill=True)
                    row = cur.fetchone()

               pdf.ln('')
               pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving endpoints_missing_details')


def get_anonymous_name(value, dictionary, index, label):

#    print('Entering get_anonymous_name for: ',value,' From: ', dictionary, ' Index=',index)
    if value not in dictionary:
        index+=1
        name=label+'_'+str(index)
        dictionary[value]=name
#        print('Value=',value,' Name=',name,' Index=',index)
    else:
        name=dictionary[value]
#    print('Leaving get_anonymous_name for: ',value,' Label: ', name)
    return name,index


############################################# 
# Alerts
def alerts(conn, pdf):

     global ANON_ALERT_FILTER

     if DEBUG:
         print('Entering alerts')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top ClearPass Cluster Alerts')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment1=section['comment1']     
          comment2=section['comment2']     
          comment3=section['comment3']     
          comment4=section['comment4']     
          threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          replace1=section['replace1']
          replace2=section['replace2']
          replace3=section['replace3']
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10

          cmd = "SELECT count(alerts) AS total, alerts, service_name FROM cppm_alerts WHERE timestamp >= '{}' AND timestamp < '{}' AND alerts NOT LIKE '{}' GROUP BY service_name, alerts ORDER BY total DESC LIMIT 10".format(START,END,whitelist) 
#          print(cmd)
          cur.execute(cmd)

          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          #pdf.cell(0, h, comment2+str(red_threshold)+comment3+str(amber_threshold), 0, 1, 'L')

          pdf.cell(20, h, "Totals", 0, 0, 'L')
          pdf.cell(55, h, "Service Name", 0, 0, 'L')
          pdf.cell(180, h, "Alert", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print("Row=", row)
               REVIEW['alerts']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    color="Red"
                    REVIEW['alerts']='High'
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    color="Amber"
                    if REVIEW['alerts']!='High':
                         REVIEW['alerts']='Med'
               else:
                    pdf.set_fill_color(255,255,255)
                    color='Normal'

#               print("color=", color, ", count=", row[0], ", service=", row[2], ", alert", row[1])
               pdf.cell(20, H, str(row[0]), 0, 0, 'L', True)
               pdf.cell(55, H, row[2], 0, 0, 'L', True)
#               pdf.cell(180, H, row[1], 0, 1, 'L', True)
               if replace1:
                   name=row[1].replace(replace1,'XXXXX')
               else: 
                   name=row[1]
               if replace2:
                   name=name.replace(replace2,'YYYYY')
               if replace3:
                   name=name.replace(replace3,'ZZZZZ')
               pdf.multi_cell(180, H, name, 0, 'L', True)
               pdf.ln(1)
               row = cur.fetchone()

          if whitelist:
               pdf.ln('')
               pdf.cell(0, H, comment4+"Alert Whitelist '"+whitelist+"'", 0, 1, 'L')

          pdf.ln('')
          pdf.multi_cell(0, H, comment1, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving alerts')


############################################# 
# Alerts graph against Time
def alerts_graph(conn, pdf):

     global FILE_INDEX

     if DEBUG:
         print('Entering alerts_graph')
     cur = conn.cursor()
     times=[]
     errors=[]
     red_list=[0]*3
     red_dates=[date(2020,1,1)]*3

     try:
          section = configdb('report.ini', 'ClearPass Error Alerts per hour')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          whitelist=section['whitelist']     
          threshold=int(section['threshold'])
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

     # execute a statement
          plt.title(heading)
          plt.ylabel('error alerts')
          plt.xlabel('date')
          plt.xticks(rotation=90)
          plt.grid(True)

          cmd = "SELECT Auth_hour, COUNT(alerts) FROM (SELECT date_trunc('hour', timestamp) AS Auth_hour, alerts FROM cppm_alerts WHERE timestamp >= '{}' AND timestamp < '{}' AND alerts NOT LIKE '{}') tmp GROUP BY Auth_hour ORDER BY Auth_hour ASC".format(START,END,whitelist)
#          print(cmd)
          cur.execute(cmd)

               # get start time
          t=datetime.strptime(START, '%Y-%m-%d')
          end=datetime.strptime(END, '%Y-%m-%d')
               # add timezone
               # as return from SQL includes timezone
          expect_time = t.replace(tzinfo=timezone('UTC'))
          end_time = end.replace(tzinfo=timezone('UTC'))
          row = cur.fetchone()
          while row is not None:
#               if DEBUG:
#                   print('Row=',row)
               timestamp = row[0]

               error = int(row[1])
               if error>threshold:
                    red_list, red_dates=update_red_date(error,timestamp, red_list, red_dates)
                    REVIEW['events']='High'

                    # Fill in any missing gaps
               while timestamp > expect_time:
#                    print('missing @', expect_time, 'got', timestamp)
                    times.append(expect_time)
                    errors.append(0)
                    expect_time = expect_time + timedelta(hours=1)
               expect_time = expect_time + timedelta(hours=1)
               times.append(timestamp)
               errors.append(error)
               row = cur.fetchone()

          while expect_time<=end_time:
#               print('end missing @', expect_time, 'got', timestamp)
               times.append(expect_time)
               errors.append(0)
               expect_time = expect_time + timedelta(hours=1)

#          print('Time, Errors')
#          j=0
#          for i in times:
#               print(i, errors[j])
#               j+=1

          plt.plot(times, errors,'r-')

#          plt.show()

               # WARNING I change the file name on each one as Linux 
               # seems to cache the first one and uses that!
               # OK a Linux flush might fix this but easier to 
               # just have unique graphs
          FILE_INDEX+=1
          filename='graph'+str(FILE_INDEX)
          plt.savefig(filename, format='png', bbox_inches='tight')
          plt.close()

          pdf.image(filename, w=LAND_W, h=GRAPH_H, type='PNG')
          if os.path.exists(filename):
               os.remove(filename)

          pdf.set_font("Arial", size = 11)
          if whitelist:
               pdf.ln('')
               pdf.cell(0, H, "NOTE: Alert Whitelist '"+whitelist+"'", 0, 1, 'L')

          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if DEBUG:
              print('Leaving alerts_graph, red_dates=',red_dates)
          return red_dates


############################################# 
# Events
def events(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_CPPM
     global ANON_CPPM_NO
     global ANON_CPPM_DIC

     if DEBUG:
         print('Entering events')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top ClearPass Cluster Events')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          replace1=section['replace1']
          replace2=section['replace2']
          replace3=section['replace3']
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd = "SELECT count(cppm_system_events.level) AS total, cppm_cluster.hostname, source, level, category, action, description FROM cppm_system_events JOIN cppm_cluster ON cppm_system_events.cppm_uuid=cppm_cluster.uuid WHERE timestamp >= '{}' AND timestamp < '{}' AND cppm_system_events.level != 'INFO' GROUP BY source, level, category, action, category, description, cppm_cluster.hostname ORDER BY total DESC LIMIT 10".format(START,END) 
#          print(cmd)
          cur.execute(cmd)

          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: ERROR in Red & WARNING in Amber", 0, 1, 'L')

          pdf.cell(15, h, "Count", 0, 0, 'L')
          pdf.cell(30, h, "ClearPass", 0, 0, 'L')
          pdf.cell(50, h, "Source", 0, 0, 'L')
          pdf.cell(20, h, "Level", 0, 0, 'L')
          pdf.cell(35, h, "Category", 0, 0, 'L')
#          pdf.cell(20, h, "Action", 0, 0, 'L')
          pdf.cell(0, h, "Description", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,0,0)
               REVIEW['events']=''
               if row[3] == 'ERROR':
                    pdf.set_fill_color(255,0,0)
                    REVIEW['events']='High'
               elif row[3] == 'WARN':
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['events']!='High':
                         REVIEW['events']='Med'
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               if ANON_CPPM:
                    name,ANON_CPPM_NO=get_anonymous_name(row[1], ANON_CPPM_DIC, ANON_CPPM_NO, 'AnonCPPM')
               else:
                    name=row[1]
               pdf.cell(30, H, name, 0, 0, 'L', True)
               pdf.cell(50, H, row[2], 0, 0, 'L', True)
               pdf.cell(20, H, row[3], 0, 0, 'L', True)
               pdf.cell(35, H, row[4], 0, 0, 'L', True)
#               pdf.cell(20, H, row[5], 0, 0, 'L', True)
#               pdf.cell(60, H, row[6], 0, 0, 'L', True)

               name=row[6]
               if replace1:
                   name=name.replace(replace1,'XXXXX')
               if replace2:
                   name=name.replace(replace2,'YYYYY')
               if replace3:
                   name=name.replace(replace3,'ZZZZZ')
               pdf.multi_cell(120, H, name, 0, 'L', True)
               pdf.ln(1)
               row = cur.fetchone()

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving events')


############################################# 
# Events graph against Time
def events_graph(conn, pdf):

     global FILE_INDEX

     if DEBUG:
         print('Entering events_graph')
     cur = conn.cursor()
     times=[]
     errors=[]
     red_list=[0]*3
     red_dates=[date(2020,1,1)]*3

     try:
          section = configdb('report.ini', 'ClearPass Error Events per hour')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

     # execute a statement
          plt.title(heading)
          plt.ylabel('error events')
          plt.xlabel('date')
          plt.xticks(rotation=90)
          plt.grid(True)

                # row[0]    hour
                # row[1]    count
          cmd = "SELECT Auth_hour, COUNT(level) FROM (SELECT date_trunc('hour', timestamp) AS Auth_hour, level FROM cppm_system_events WHERE timestamp >= '{}' AND timestamp < '{}' AND level='ERROR') tmp GROUP BY Auth_hour ORDER BY Auth_hour ASC".format(START,END)
#          print(cmd)
          cur.execute(cmd)

               # get start time
          t=datetime.strptime(START, '%Y-%m-%d')
          end=datetime.strptime(END, '%Y-%m-%d')

               # add timezone
               # as return from SQL includes timezone
          expect_time = t.replace(tzinfo=timezone('UTC'))
          end_time = end.replace(tzinfo=timezone('UTC'))
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               timestamp = row[0]
               error = int(row[1])
               if error>threshold:
                    red_list, red_dates=update_red_date(error,timestamp, red_list, red_dates)
                    REVIEW['events']='High'

                    # Fill in any missing gaps
               while timestamp > expect_time:
                    if DEBUG:
                        print('missing @', expect_time, 'got', timestamp)
                    times.append(expect_time)
                    errors.append(0)
                    expect_time = expect_time + timedelta(hours=1)
               expect_time = expect_time + timedelta(hours=1)
               times.append(timestamp)
               errors.append(error)
               row = cur.fetchone()

          while expect_time < end_time:
               if DEBUG:
                    print('end missing @', expect_time, 'got', timestamp)
               times.append(expect_time)
               errors.append(0)
               expect_time = expect_time + timedelta(hours=1)

          plt.plot(times, errors,'r-')

#          plt.show()

               # WARNING I change the file name on each one as Linux 
               # seems to cache the first one and uses that!
               # OK a Linux flush might fix this but easier to 
               # just have unique graphs
          FILE_INDEX+=1
          filename='graph'+str(FILE_INDEX)
          plt.savefig(filename, format='png', bbox_inches='tight')
          plt.close()

          pdf.image(filename, w=PORT_W, h=GRAPH_H, type='PNG')
          if os.path.exists(filename):
               os.remove(filename)

          pdf.set_font("Arial", size = 11)
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          pdf.cell(0, h, "NOTE: Burst Threshold="+str(threshold), 0, 1, 'L')
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)

          if DEBUG:
              print('Leaving events_graph, red_dates=',red_dates)
          return red_dates


def update_red_date(count, timestamp, red_list, red_date):

#    print('count=',count,', type=',type(count))
    if count>red_list[0]:
#        print('Update 1st=',count)
        red_list[2]=red_list[1]
        red_date[2]=red_date[1]
        red_list[1]=red_list[0]
        red_date[1]=red_date[0]
        red_list[0]=count
        red_date[0]=timestamp
    elif count>red_list[1]:
#        print('Update 2nd=',count)
        red_list[2]=red_list[1]
        red_date[2]=red_date[1]
        red_list[1]=count
        red_date[1]=timestamp
    elif count>red_list[2]:
#        print('Update 3rd=',count)
        red_list[2]=count
        red_date[2]=timestamp
    return red_list, red_date


############################################# 
# Endpoint Categorization Breakdown
def endpoint_categories(conn, pdf):

     if DEBUG:
         print('Entering endpoint_categories')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Endpoint Categorization')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd="SELECT COALESCE(device_category, 'No Fingerprint'), COUNT(mac) FROM endpoints WHERE updated_at >= '{}' AND updated_at < '{}' GROUP BY device_category LIMIT 10".format(START,END)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()
               # row[0] device category
               # row[1] count

          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(50, h, '', 0, 0, 'L')
          pdf.cell(75, h, 'Category', 0, 0, 'L')
          pdf.cell(50, h, 'Total', 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               alert=False
               REVIEW['endpoints_categories']=''
               if row[0] == 'No Fingerprint': 
                    pdf.set_fill_color(255,0,0)
                    alert=True
                    REVIEW['endpoints_categories']='High'
               elif row[0] == 'Generic':
                    pdf.set_fill_color(255,194,0)
                    alert=True
                    if REVIEW['endpoints_categories']!='High':
                         REVIEW['endpoints_categories']='Med'
               pdf.cell(50, h, '', 0, 0, 'L')
               pdf.cell(75, H, row[0], 0, 0, 'L')
               pdf.cell(50, H, str(row[1]), 0, 1, 'L', fill=alert)
               row = cur.fetchone()

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving endpoint_categories')


############################################# 
# Endpoint MAC Spoof
def endpoint_spoof(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC

     if DEBUG:
        print('Entering endpoint_spoof')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Number of Suspected Spoofs Detected')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          whitelist=section['whitelist_mac']
          whitelist_mac=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd="SELECT count(mac) AS spoof FROM endpoints WHERE conflict IS True AND updated_at >= '{}' AND updated_at < '{}' LIMIT 10".format(START,END)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()
               # row[0] spoof count

          pdf.set_font("Arial", size = 11)
          alert=False
          pdf.set_fill_color(255,255,255)
          if row[0] > 0: 
               pdf.set_fill_color(255,0,0)
               REVIEW['endpoint_spoof']='High'
               alert=True
          pdf.cell(50, h, "", 0, 0, 'C')
          pdf.cell(50, h, str(row[0]), 0, 1, 'C', fill=alert)

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          pdf.ln('')
          
          if row[0] > 0:
               section = configdb('report.ini', '10 Most Recent Spoof')
               heading=section['title']     
               print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
               pdf.set_font("Arial", 'B', size = 14)
               pdf.set_fill_color(255,0,0)
               pdf.cell(0, h, heading, 0, 1, 'L')

               cmd="SELECT mac, COALESCE(mac_vendor,''), COALESCE(ip,''), static_ip, COALESCE(hostname,''), COALESCE(username,''), nad_ip, nas_port_type, nad_port, ssid, device_category, device_family, device_name, other_category, other_family, other_name FROM endpoints WHERE conflict IS True AND updated_at >= '{}' AND updated_at < '{}' AND mac NOT IN ('{}') ORDER BY updated_at DESC LIMIT 10".format(START,END,whitelist_mac)
#               print('Spoof sql=', cmd)
               cur.execute(cmd)
                    # row[0]=mac
                    # row[1]=mac_vendor
                    # row[2]=ip
                    # row[3]=static_ip
                    # row[4]=hostname
                    # row[5]=username
                    # row[6]=nad_ip
                    # row[7]=nas_port_type
                    # row[8]=nad_port
                    # row[9]=ssid
                    # row[10]=device_category
                    # row[11]=device_family
                    # row[12]=device_name
                    # row[13]=other_category
                    # row[14]=other_family
                    # row[15]=other_name          

               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(30, h, "MAC", 0, 0, 'L')
               pdf.cell(35, h, "Category", 0, 0, 'L')
               pdf.cell(40, h, "Family", 0, 0, 'L')
               pdf.cell(40, h, "DevType", 0, 0, 'L')
               pdf.cell(35, h, "Spoof Category", 0, 0, 'L')
               pdf.cell(40, h, "Spoof Family", 0, 0, 'L')
               pdf.cell(40, h, "Spoof DevType", 0, 1, 'L')

               pdf.set_font("Arial", size = 11)
               row = cur.fetchone()
               while row is not None:
                    if DEBUG:
                        print('Row=',row)
                    if ANON_MAC:
                        name,ANON_MAC_NO=get_anonymous_name(row[0], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
                    else:
                        name=row[0]
                    pdf.cell(30, H, name, 0, 0, 'L', fill=True)
                    pdf.cell(35, H, row[10], 0, 0, 'L', fill=True)
                    pdf.cell(40, H, row[11], 0, 0, 'L', fill=True)
                    pdf.cell(40, H, row[12], 0, 0, 'L', fill=True)
                    pdf.cell(35, H, row[13], 0, 0, 'L', fill=True)
                    pdf.cell(40, H, row[14], 0, 0, 'L', fill=True)
                    pdf.cell(40, H, row[15], 0, 1, 'L', fill=True)
                    row = cur.fetchone()

          if ANON_MAC is False:
            if whitelist_mac:
               pdf.ln('')
               pdf.cell(0, H, "NOTE: MAC Whitelist "+whitelist, 0, 0, 'L')

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving endpoint_spoof')


############################################# 
# Authentications per Service
def auths_per_service(conn, pdf):

     global ANON_SERVICE
     global ANON_SERVICE_DIC
     global ANON_SERVICE_NO

     if DEBUG:
        print('Entering auths_per_service')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Authentications per Service')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd = "SELECT COALESCE(service,'No Match'), COUNT(*) AS total, COUNT(*) FILTER (WHERE error_code = 0), 100*(COUNT(*) FILTER (WHERE error_code = 0))/COUNT(*), COUNT(*) FILTER (WHERE error_code != 0), 100*(COUNT(*) FILTER (WHERE error_code != 0))/COUNT(*) FROM auth WHERE timestamp >= '{}' AND timestamp < '{}' GROUP BY auth.service ORDER BY total DESC".format(START,END) 
#          print(cmd)
          cur.execute(cmd)

          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(120, h, "Service", 0, 0, 'L')
          pdf.cell(30, h, "Total", 0, 0, 'L')
          pdf.cell(30, h, "Successes", 0, 0, 'L')
          pdf.cell(30, h, "Failures", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                    print('Row=',row)
               pdf.cell(30, H, "", 0, 0, 'L')
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[0], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[0]
               pdf.cell(120, H, name, 0, 0, 'L')
               pdf.cell(30, H, str(row[1]), 0, 0, 'L')
               pdf.cell(30, H, str(row[2]), 0, 0, 'L')
               pdf.cell(30, H, str(row[4]), 0, 1, 'L')
               row = cur.fetchone()

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
                print('Leaving auths_per_service')


############################################# 
# Failures per Service 
def fails_per_service(conn, pdf):

     global ANON_SERVICE
     global ANON_SERVICE_DIC
     global ANON_SERVICE_NO

     if DEBUG:
        print('Entering fails_per_service')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Failed Authentications per Service')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd = "SELECT COALESCE(service,'No Match'), COUNT(*) AS total, COUNT(*) FILTER (WHERE error_code = 0) AS success, 100*(COUNT(*) FILTER (WHERE error_code = 0))/COUNT(*) AS s_percent, COUNT(*) FILTER (WHERE error_code != 0) AS failed, 100*(COUNT(*) FILTER (WHERE error_code != 0))/COUNT(*) AS f_percent FROM auth WHERE timestamp >= '{}' AND timestamp < '{}' GROUP BY service ORDER BY f_percent DESC, failed DESC LIMIT 15".format(START,END) 
#          print(cmd)
          cur.execute(cmd)

          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red >= 50% & Amber >= 25%", 0, 1, 'L')
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(120, h, "Service", 0, 0, 'L')
          pdf.cell(25, h, "Total", 0, 0, 'L')
          pdf.cell(25, h, "Successes", 0, 0, 'L')
          pdf.cell(25, h, "Failures", 0, 0, 'L')
          pdf.cell(10, h, "% Failed", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                    print('Row=',row)
               REVIEW['fails_per_service']=''
               if (row[5] >= 50):
                    pdf.set_fill_color(255,0,0)
                    REVIEW['fails_per_service']='High'
               elif (row[5] >= 25):
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['fails_per_service']!='High':
                         REVIEW['fails_per_service']='Med'
               else:
                    pdf.set_fill_color(255,255,255)
               pdf.cell(30, H, "", 0, 0, 'L')
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[0], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[0]
               pdf.cell(120, H, name, 0, 0, 'L', True)
               pdf.cell(25, H, str(row[1]), 0, 0, 'L', True)
               pdf.cell(25, H, str(row[2]), 0, 0, 'L', True)
               pdf.cell(25, H, str(row[4]), 0, 0, 'L', True)
               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(10, H, str(row[5]), 0, 1, 'L', True)
               pdf.set_font("Arial", size = 11)
               row = cur.fetchone()

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
                print('Leaving fails_per_service')


############################################# 
# Successes per Service 
def success_per_service(conn, pdf):

     global ANON_SERVICE
     global ANON_SERVICE_DIC
     global ANON_SERVICE_NO

     if DEBUG:
         print('Entering success_per_service')
     cur = conn.cursor()
     try:
          cmd = "SELECT COALESCE(service,'No Match'), COUNT(*) AS total, COUNT(*) FILTER (WHERE error_code = 0) AS success, 100*(COUNT(*) FILTER (WHERE error_code = 0))/COUNT(*) AS s_percent, COUNT(*) FILTER (WHERE error_code != 0) AS failed, 100*(COUNT(*) FILTER (WHERE error_code != 0))/COUNT(*) AS f_percent FROM auth WHERE timestamp >= '{}' AND timestamp < '{}' GROUP BY service ORDER BY s_percent DESC, success DESC LIMIT 10".format(START,END) 
#          print(cmd)
          cur.execute(cmd)

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, "Top Successful Authentications per Service", 0, 1, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(80, h, "Service", 0, 0, 'L')
          pdf.cell(25, h, "Total", 0, 0, 'L')
          pdf.cell(25, h, "Successes", 0, 0, 'L')
          pdf.cell(25, h, "Failures", 0, 0, 'L')
          pdf.cell(10, h, "% Success", 0, 1, 'L')

          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               if (row[5] >= 75):
                    pdf.set_fill_color(255,0,0)
               elif (row[5] >= 50):
                    pdf.set_fill_color(255,194,0)
               else:
                    pdf.set_fill_color(255,255,255)
               pdf.cell(30, h, "", 0, 0, 'L')
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[0], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[0]
               pdf.cell(80, h, name, 0, 0, 'L', True)
               pdf.cell(25, h, str(row[1]), 0, 0, 'L', True)
               pdf.cell(25, h, str(row[2]), 0, 0, 'L', True)
               pdf.cell(25, h, str(row[4]), 0, 0, 'L', True)
               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(10, h, str(row[3]), 0, 1, 'L', True)
               pdf.set_font("Arial", size = 11)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving success_per_service')


############################################# 
# Null Service 
def null_service(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC

     if DEBUG:
         print('Entering null_service')
     red_list=[]

     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Endpoints not Matching a Service')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist_mac=section['whitelist_mac']     
          whitelist_mac=whitelist_mac.replace(",","','")     # replace the coma with ',' so that SQL will work
          whitelist_user=section['whitelist_user']     
          whitelist_user=whitelist_user.replace(",","','")     # replace the coma with ',' so that SQL will work
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd = "SELECT count(*) AS Matches, COALESCE(auth.mac,''), auth.username, nads.name, auth.nad_ip, auth.nas_port_type, COALESCE(auth.nas_port_id, '') AS Port, COALESCE(auth.ssid, '') AS SSID FROM auth JOIN nads ON auth.nad_ip = nads.ip LEFT JOIN endpoints ON auth.mac = endpoints.mac WHERE timestamp >= '{}' AND timestamp < '{}' AND auth.service IS NULL AND auth.service IS NULL AND (auth.mac NOT IN ('{}') OR auth.username NOT IN ('{}')) GROUP BY auth.mac, auth.username, auth.nad_ip, auth.nas_port_type, nads.name, auth.nas_port_id, auth.ssid ORDER BY Matches DESC LIMIT 15".format(START,END,whitelist_mac, whitelist_user) 
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     mac
               # row[2]     username
               # row[3]     NAS
               # row[4]     NAS IP
               # row[5]     Media (value 5, 15, 19)
               # row[6]     Port
               # row[7]     SSID

          pdf.set_font("Arial", 'B', size = 11)
#          print('Red=',red_threshold,', Amber=',amber_threshold,', daily rate=',threshold)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
#          pdf.cell(0, h, ,str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(15, h, "#", 0, 0, 'L')
          pdf.cell(30, h, "MAC", 0, 0, 'L')
          pdf.cell(60, h, "Username", 0, 0, 'L')
          pdf.cell(60, h, "NAS", 0, 0, 'L')
          pdf.cell(30, h, "NAS IP", 0, 0, 'L')
          pdf.cell(15, h, "Media", 0, 0, 'L')
          pdf.cell(20, h, "Port/SSID", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               REVIEW['null_service']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[1])
                    REVIEW['null_service']='High'
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['null_service']!='High':
                         REVIEW['null_service']='Med'
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(row[1], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=row[1]
               pdf.cell(30, H, name, 0, 0, 'L', True)
               value=normalize_mac(row[2])
               if row[2]=='':
                   name=''
               elif row[1]==value:
                    name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[2], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[2]
               pdf.cell(60, H, name, 0, 0, 'L', True)
               if ANON_NAS:
                    name,ANON_NAS_NO=get_anonymous_name(row[4], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                    name2=name
               else:
                    name=row[3]
                    name2=row[4]
               pdf.cell(60, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, name2, 0, 0, 'L', True)
               if row[5] == '5':
                    pdf.set_fill_color(255,194,0)
                    media = 'Virtual'
                    value = ''
               elif row[5] == '15':
                    media = 'Wired'
                    value = row[6]
               elif row[5] == '19':
                    media = 'Wifi'
                    value = row[7]
               else:
                    pdf.set_fill_color(255,0,0)
                    media = row[5]
                    value = ''
                    red_list.append(row[1])
               pdf.cell(15, H, media, 0, 0, 'L', True)
               pdf.cell(30, H, value, 0, 1, 'L', True)
               row = cur.fetchone()

          if ANON_MAC is False:
             if whitelist_mac:     
               pdf.ln('')
               pdf.cell(0, H, 'MAC Whitelist '+section['whitelist_mac'], 0, 1, 'L')
          if ANON_USER is False:
            if whitelist_user:
               pdf.ln('')
               pdf.cell(0, H, 'Username Whitelist '+section['whitelist_user'], 0, 1, 'L')

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)

          if DEBUG:
              print('Leaving null_service, red_list=',red_list)
          return red_list


############################################# 
# Top Wired Endpoints with most Auths
def wired_endpoint_auths(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC

     red_list=[]

     if DEBUG:
         print('Entering wired_endpoint_auths')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Wired Endpoints Auths')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd = "SELECT count(*) AS total, count(*) FILTER (WHERE error_code=0), count(*) FILTER (WHERE error_code!=0), COALESCE(mac,'Null!') FROM auth WHERE nas_port_type='15' AND timestamp >= '{}' AND timestamp < '{}' AND mac NOT IN ('{}') GROUP BY auth.mac ORDER BY total DESC LIMIT 15".format(START,END,whitelist) 
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     failed (value)
               # row[2]     success (value)
               # row[3]     mac

          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(20, h, "Auths", 0, 0, 'L')
          pdf.cell(20, h, "Success", 0, 0, 'L')
          pdf.cell(20, h, "Failed", 0, 0, 'L')
          pdf.cell(30, h, "MAC", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               REVIEW['wired_endpoint_auths']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[3])
                    REVIEW['wired_endpoint_auths']='High'
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['wired_endpoint_auths']!='High':
                         REVIEW['wired_endpoint_auths']='Med'
               pdf.cell(30, H, "", 0, 0, 'L')
               pdf.cell(20, H, str(row[0]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[1]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[2]), 0, 0, 'L', True)
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(row[3], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=row[3]
               pdf.cell(30, H, name, 0, 1, 'L', True)
               row = cur.fetchone()

          pdf.ln('')
          if ANON_MAC is False:
            if whitelist:
               pdf.cell(0, h, "MAC whitelist "+section['whitelist'], 0, 1, 'L')
               pdf.ln('')

          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)

          if DEBUG:
              print('Leaving wired_endpoint_auths, red_list=',red_list)
          return red_list


############################################# 
# Top Wired Endpoints with most Auths in a an hour
def wired_endpoint_auths_burst(conn, pdf, done_list):

     red_list=[]

     if DEBUG:
        print('Entering wired_endpoint_auths_burst, done_list=',done_list)
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Wired Burst Authentications per hour')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          red_threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work

          amber_threshold=red_threshold*2//3
          
          cmd = "SELECT count(*) AS total, COALESCE(mac,'Null!') AS mac FROM (SELECT date_trunc('hour',auth.timestamp) AS Auth_hour, mac FROM auth WHERE nas_port_type='15' AND timestamp >= '{}' AND timestamp < '{}' AND mac NOT IN ('{}')) tmp GROUP BY auth_hour, mac ORDER BY total DESC".format(START,END,whitelist) 
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     mac

               # This SQL is suboptimal and is not returning unique 
               # list of MAC addresses. To address this I use the 
               # python to return the worst MAC addresses
               # Sure this is not great python but should work ;-)
          row = cur.fetchone()
          count=0
          while row is not None: 
#               if DEBUG:
#                    print('Row=',row)
               if row[0]>red_threshold:
                        # Only first 3 previous one examined in details
                   if row[1] not in done_list:
                       if row[1] not in red_list:
                            red_list.append(row[1])
                                    # Only record the top 3
                            count+=1
                            if count>=3:
                                break
               elif row[0]<red_threshold:
                   break
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if len(red_list)==0:
               pdf.ln(h)

          if DEBUG:
                print('Leaving wired_endpoint_auths_burst, red_list=',red_list)
          return red_list


############################################# 
# Top Wireless Endpoints with most Auths in a an hour
def wireless_endpoint_auths_burst(conn, pdf, done_list):

     red_list=[]

     if DEBUG:
        print('Entering wireless_endpoint_auths_burst, done_list=',done_list)
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Wireless Burst Authentications per hour')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          red_threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work

#          print('red_threshold=',red_threshold)
          amber_threshold=red_threshold*2//3
          
          cmd = "SELECT count(*) AS total, COALESCE(mac,'Null!') AS mac FROM (SELECT date_trunc('hour',auth.timestamp) AS Auth_hour, mac FROM auth WHERE nas_port_type='19' AND timestamp >= '{}' AND timestamp < '{}' AND mac NOT IN ('{}')) tmp GROUP BY auth_hour, mac ORDER BY total DESC".format(START,END,whitelist) 
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     mac

               # This SQL is suboptimal and is not returning unique 
               # list of MAC addresses. To address this I use the 
               # python to return the worst MAC addresses
               # Sure this is not great python but should work ;-)
          row = cur.fetchone()
          count=0
          while row is not None: 
               if DEBUG:
                    print('Row=',row)
               if row[0]>red_threshold:
                        # Only first 3 previous one examined in details
                   if row[1] not in done_list:
                       if row[1] not in red_list:
                            red_list.append(row[1])
                            count+=1
                            if count>=3:
                                break
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if len(red_list)==0:
               pdf.ln(h)

          if DEBUG:
                print('Leaving wireless_endpoint_auths_burst, red_list=',red_list)
          return red_list


############################################# 
# Create graph of wired endpoint's burst auths per hour
def endpoints_wired_burst_auth_graph(conn, pdf, red_list):

    global ANON_MAC
    global ANON_MAC_NO
    global ANON_MAC_DIC
    global FILE_INDEX

    if DEBUG:
        print('Entering endpoints_wired_burst_auth_graph. red_list', red_list)
    cur=conn.cursor()
    times=[]
    successes=[]
    failures=[]
    try:
        section = configdb('report.ini', 'Top Wired Burst Authentications per hour')
        heading=section['title']     
        print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
        comment=section['comment']     
        whitelist=section['whitelist']     
        whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work
          
        f=plt.figure()
        plt.title(heading)
        plt.ylabel('authentications')
        plt.xlabel('time')
        plt.xticks(rotation=90)
        plt.grid(True)

        string=''
        for mac in red_list:
            if mac=='':
                break
            if string=='':
                string='\''+mac+'\''
            else: 
                string=string+',\''+mac+'\''
        if string=='':
                return      # nothing to graph
        count=0
        cmd="SELECT Auth_hour, mac, COUNT(error_code) FILTER (WHERE error_code = 0) AS Success, COUNT(error_code) FILTER (WHERE error_code !=0) AS Failed FROM (SELECT date_trunc('hour', auth.timestamp) AS Auth_hour, mac, error_code FROM auth WHERE mac IN ({}) AND timestamp >= '{}' AND timestamp < '{}' AND mac NOT IN ('{}')) tmp GROUP BY Auth_hour, mac ORDER BY mac, Auth_hour ASC".format(string,START,END,whitelist)
        print(cmd)
        cur.execute(cmd)

            # row[0]    auth_hour
            # row[1]    mac
            # row[2]    success
            # row[3]    fail

              # get start time
        t=datetime.strptime(START, '%Y-%m-%d')
        end=datetime.strptime(END, '%Y-%m-%d')
        # add timezone
        # as return from SQL includes timezone
        expect_time = t.replace(tzinfo=timezone('UTC'))
        end_time = end.replace(tzinfo=timezone('UTC'))
        row = cur.fetchone()
        mac=row[1]
        while row is not None:
            if DEBUG:
                print('Row=',row,', expect_time=',expect_time)

                # Have we got another MAC address?
            if row[1]!=mac:
#                print('Another endpoint=',mac)

#                print('expect_time=',expect_time,' end_time=',end_time)
                    # Fill in any missing to end_time
                while expect_time<=end_time:
#                    print('end missing1 @', expect_time, 'got', timestamp)
                    times.append(expect_time)
                    successes.append(0)
                    failures.append(0)
                    expect_time = expect_time + timedelta(hours=1)

                    # Print graph for this endpoint
                if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
                else:
                    name=mac
                hostname=name+' success'
#                print('Plot', hostname)
                x, = plt.plot(times, successes, label=hostname)
                x.set_label(hostname)
                hostname=mac+' failed'
#                print('Plot', hostname)
                y, = plt.plot(times, failures, label=hostname)
                y.set_label(hostname)

                    # Move on to get the next device
                del times[:]
                del successes[:]
                del failures[:]
                expect_time = t.replace(tzinfo=timezone('UTC'))

                    # Update the mac
                mac = row[1]

            timestamp = row[0]
            success = row[2]
            failed = row[3]

                # Fill in any missing gaps
#            print('time=',timestamp,', expect=',expect_time)
            while timestamp > expect_time:
#                print('missing @', expect_time, 'got', timestamp)
                times.append(expect_time)
                successes.append(0)
                failures.append(0)
                expect_time = expect_time + timedelta(hours=1)

            times.append(timestamp)
            successes.append(success)
            failures.append(failed)
            expect_time = expect_time + timedelta(hours=1)
            row = cur.fetchone()

        while expect_time<=end_time:
#           print('end missing @', expect_time, 'got', timestamp)
            times.append(expect_time)
            successes.append(0)
            failures.append(0)
            expect_time = expect_time + timedelta(hours=1)

            # Print last device graph
        if ANON_MAC:
            name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
        else:
            name=mac
        hostname=name+' success'
#        print('Plot', hostname)
        x, = plt.plot(times, successes, label=hostname)
        x.set_label(hostname)
        hostname=name+' failed'
#        print('Plot', hostname)
        y, = plt.plot(times, failures, label=hostname)
        y.set_label(hostname)
          

        FILE_INDEX+=1
        filename='graph'+str(FILE_INDEX)
        plt.legend()
#        plt.show()
        plt.savefig(filename, format='png', bbox_inches='tight')

            # WARNING I change the file name on each one as Linux 
            # seems to cache the first one and uses that!
            # OK a Linux flush might fix this but easier to 
            # just have unique graphs
        plt.clf()
        plt.close()

        pdf.image(filename, w=LAND_W, h=GRAPH_H, type='PNG')
        if os.path.exists(filename):
             os.remove(filename)
             
        if ANON_MAC is False:
            if whitelist:
                pdf.cell(0, h, "MAC whitelist "+section['whitelist'], 0, 1, 'L')
                pdf.ln('')

        pdf.set_font("Arial", size = 11)
        pdf.multi_cell(0, H, comment, 0, 'L', False)
          
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        pdf.ln(h)
        if DEBUG:
            print('Leaving endpoints_wired_burst_auth_graph')


############################################# 
# Create graph of endpoint's
def endpoints_auth_graph(conn, pdf, label, red_list):

    global ANON_MAC
    global ANON_MAC_NO
    global ANON_MAC_DIC
    global FILE_INDEX

    if DEBUG:
        print('Entering endpoints_auth_graph. red_list=', red_list)
    cur=conn.cursor()
    times=[]
    successes=[]
    failures=[]
    try:
        section = configdb('report.ini', label)
        heading=section['title']     
        print('\t'+heading+' graph (timestamp='+str(datetime.now().time())+')')
        comment=section['comment']     
        whitelist=section['whitelist']     
        whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work
          
        f=plt.figure()
        plt.title(heading)
        plt.ylabel('authentications')
        plt.xlabel('time')
        plt.xticks(rotation=90)
        plt.grid(True)

        string=''
        for mac in red_list:
            if mac=='':
                break
            if string=='':
                string='\''+mac+'\''
            else: 
                string=string+',\''+mac+'\''
        if string=='':
            return      # Nothing to graph
        count=0
        cmd="SELECT Auth_hour, mac, COUNT(error_code) FILTER (WHERE error_code = 0) AS Success, COUNT(error_code) FILTER (WHERE error_code !=0) AS Failed FROM (SELECT date_trunc('hour', auth.timestamp) AS Auth_hour, mac, error_code FROM auth WHERE mac IN ({}) AND timestamp >= '{}' AND timestamp < '{}' AND mac NOT IN ('{}')) tmp GROUP BY Auth_hour, mac ORDER BY mac, Auth_hour ASC".format(string,START,END,whitelist)
#        print(cmd)
        cur.execute(cmd)

            # row[0]    auth_hour
            # row[1]    mac
            # row[2]    success
            # row[3]    fail

              # get start time
        t=datetime.strptime(START, '%Y-%m-%d')
        end=datetime.strptime(END, '%Y-%m-%d')
        # add timezone
        # as return from SQL includes timezone
        expect_time = t.replace(tzinfo=timezone('UTC'))
        end_time = end.replace(tzinfo=timezone('UTC'))
        row = cur.fetchone()
        mac=row[1]
#        print('First endpoint=',mac)
        while row is not None:
#            if DEBUG:
#                print('Row=',row,', expect_time=',expect_time)

                # Have we got another MAC address?
            if row[1]!=mac:
#                print('Another endpoint=',mac)

#                print('expect_time=',expect_time,' end_time=',end_time)
                    # Fill in any missing to end_time
                while expect_time<=end_time:
#                    print('end missing1 @', expect_time, 'got', timestamp)
                    times.append(expect_time)
                    successes.append(0)
                    failures.append(0)
                    expect_time = expect_time + timedelta(hours=1)

                    # Print graph for this endpoint
                if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
                else:
                    name=mac
                hostname=name+' success'
#                print('Plot', hostname)
                x, = plt.plot(times, successes, label=hostname)
                x.set_label(hostname)
                hostname=name+' failed'
#                print('Plot', hostname)
                y, = plt.plot(times, failures, label=hostname)
                y.set_label(hostname)

                    # Move on to get the next device
                del times[:]
                del successes[:]
                del failures[:]
                expect_time = t.replace(tzinfo=timezone('UTC'))

                    # Update the mac
                mac = row[1]

            timestamp = row[0]
            success = row[2]
            failed = row[3]

                # Fill in any missing gaps
#            print('time=',timestamp,', expect=',expect_time)
            while timestamp > expect_time:
#                print('missing @', expect_time, 'got', timestamp)
                times.append(expect_time)
                successes.append(0)
                failures.append(0)
                expect_time = expect_time + timedelta(hours=1)

            times.append(timestamp)
            successes.append(success)
            failures.append(failed)
            expect_time = expect_time + timedelta(hours=1)
            row = cur.fetchone()

            # Fill in the last endpoint's end
#        print('time=',timestamp,', expect=',expect_time)
        while expect_time<=end_time:
#            print('end missing @', expect_time, 'got', timestamp)
            times.append(expect_time)
            successes.append(0)
            failures.append(0)
            expect_time = expect_time + timedelta(hours=1)

            # Print last device graph
        if ANON_MAC:
            name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
        else:
            name=mac
        hostname=name+' success'
#        print('Plot', hostname)
        x, = plt.plot(times, successes, label=hostname)
        x.set_label(hostname)
        hostname=name+' failed'
#        print('Plot', hostname)
        y, = plt.plot(times, failures, label=hostname)
        y.set_label(hostname)
          

        plt.legend()
#        plt.show()
        
        FILE_INDEX+=1
        filename='graph'+str(FILE_INDEX)
        plt.savefig(filename, format='png', bbox_inches='tight')

            # WARNING I change the file name on each one as Linux 
            # seems to cache the first one and uses that!
            # OK a Linux flush might fix this but easier to 
            # just have unique graphs
        plt.clf()
        plt.close()

        pdf.image(filename, w=LAND_W, h=GRAPH_H, type='PNG')
        if os.path.exists(filename):
             os.remove(filename)
             
        if ANON_MAC is False:
            if whitelist:
                pdf.cell(0, h, "MAC whitelist "+section['whitelist'], 0, 1, 'L')
                pdf.ln('')

        pdf.set_font("Arial", size = 11)
        pdf.multi_cell(0, H, comment, 0, 'L', False)
          
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        pdf.ln(h)
        if DEBUG:
            print('Leaving endpoints_auth_graph')


############################################# 
# Create graph of endpoint's
def endpoints_auth_null_graph(conn, pdf, label, red_list):

    global ANON_MAC
    global ANON_MAC_NO
    global ANON_MAC_DIC
    global FILE_INDEX

    if DEBUG:
        print('Entering endpoints_auth_null_graph. red_list=', red_list)
    cur=conn.cursor()
    times=[]
    successes=[]
    failures=[]
    try:
        section = configdb('report.ini', label)
        heading=section['title']     
        print('\t'+heading+' graph (timestamp='+str(datetime.now().time())+')')
        comment=section['comment']     
        whitelist_mac=section['whitelist_mac']     
        whitelist_mac=whitelist_mac.replace(",","','")     # replace the coma with ',' so that SQL will work
        whitelist_user=section['whitelist_user']     
        whitelist_user=whitelist_user.replace(",","','")     # replace the coma with ',' so that SQL will work
          
        f=plt.figure()
        plt.title(heading)
        plt.ylabel('authentications')
        plt.xlabel('time')
        plt.xticks(rotation=90)
        plt.grid(True)

        string=''
        for mac in red_list:
            if mac=='':
                break
            if string=='':
                string='\''+mac+'\''
            else: 
                string=string+',\''+mac+'\''
        if string=='':      # if nothing in the red_list
            return
        count=0

        cmd="SELECT Auth_hour, mac, COUNT(error_code) FILTER (WHERE error_code = 0) AS Success, COUNT(error_code) FILTER (WHERE error_code !=0) AS Failed FROM (SELECT date_trunc('hour', auth.timestamp) AS Auth_hour, mac, error_code FROM auth WHERE mac IN ({}) AND timestamp >= '{}' AND timestamp < '{}' AND mac NOT IN ('{}') AND username NOT IN ('{}')) tmp GROUP BY Auth_hour, mac ORDER BY mac, Auth_hour ASC".format(string,START,END,whitelist_mac,whitelist_user)
#        print(cmd)
        cur.execute(cmd)

            # row[0]    auth_hour
            # row[1]    mac
            # row[2]    success
            # row[3]    fail

              # get start time
        t=datetime.strptime(START, '%Y-%m-%d')
        end=datetime.strptime(END, '%Y-%m-%d')
        # add timezone
        # as return from SQL includes timezone
        expect_time = t.replace(tzinfo=timezone('UTC'))
        end_time = end.replace(tzinfo=timezone('UTC'))
        row = cur.fetchone()
        mac=row[1]
#        print('First endpoint=',mac)
        while row is not None:
#            if DEBUG:
#                print('Row=',row,', expect_time=',expect_time)

                # Have we got another MAC address?
            if row[1]!=mac:
#                print('Another endpoint=',mac)

#                print('expect_time=',expect_time,' end_time=',end_time)
                    # Fill in any missing to end_time
                while expect_time<=end_time:
#                    print('end missing1 @', expect_time, 'got', timestamp)
                    times.append(expect_time)
                    successes.append(0)
                    failures.append(0)
                    expect_time = expect_time + timedelta(hours=1)

                    # Print graph for this endpoint
                if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
                else:
                    name=mac
                hostname=name+' success'
#                print('Plot', hostname)
                x, = plt.plot(times, successes, label=hostname)
                x.set_label(hostname)
                hostname=name+' failed'
#                print('Plot', hostname)
                y, = plt.plot(times, failures, label=hostname)
                y.set_label(hostname)

                    # Move on to get the next device
                del times[:]
                del successes[:]
                del failures[:]
                expect_time = t.replace(tzinfo=timezone('UTC'))

                    # Update the mac
                mac = row[1]

            timestamp = row[0]
            success = row[2]
            failed = row[3]

                # Fill in any missing gaps
#            print('time=',timestamp,', expect=',expect_time)
            while timestamp > expect_time:
#                print('missing @', expect_time, 'got', timestamp)
                times.append(expect_time)
                successes.append(0)
                failures.append(0)
                expect_time = expect_time + timedelta(hours=1)

            times.append(timestamp)
            successes.append(success)
            failures.append(failed)
            expect_time = expect_time + timedelta(hours=1)
            row = cur.fetchone()

            # Fill in the last endpoint's end
#        print('time=',timestamp,', expect=',expect_time)
        while expect_time<=end_time:
#            print('end missing @', expect_time, 'got', timestamp)
            times.append(expect_time)
            successes.append(0)
            failures.append(0)
            expect_time = expect_time + timedelta(hours=1)

            # Print last device graph
        if ANON_MAC:
            name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
        else:
            name=mac
        hostname=name+' success'
#        print('Plot', hostname)
        x, = plt.plot(times, successes, label=hostname)
        x.set_label(hostname)
        hostname=name+' failed'
#        print('Plot', hostname)
        y, = plt.plot(times, failures, label=hostname)
        y.set_label(hostname)
          

        plt.legend()
#        plt.show()
        
        FILE_INDEX+=1
        filename='graph'+str(FILE_INDEX)
        plt.savefig(filename, format='png', bbox_inches='tight')

            # WARNING I change the file name on each one as Linux 
            # seems to cache the first one and uses that!
            # OK a Linux flush might fix this but easier to 
            # just have unique graphs
        plt.clf()
        plt.close()

        pdf.image(filename, w=LAND_W, h=GRAPH_H, type='PNG')
        if os.path.exists(filename):
             os.remove(filename)
             
        if ANON_MAC is False:
            if whitelist:
                pdf.cell(0, h, "MAC whitelist "+section['whitelist'], 0, 1, 'L')
                pdf.ln('')

        pdf.set_font("Arial", size = 11)
        pdf.multi_cell(0, H, comment, 0, 'L', False)
          
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        pdf.ln(h)
        if DEBUG:
            print('Leaving endpoints_auth_null_graph')


############################################# 
# Create graph of user auths
def users_auth_graph(conn, pdf, label, red_list):

    global ANON_USER
    global ANON_USER_NO
    global ANON_USER_DIC
    global FILE_INDEX

    if DEBUG:
        print('Entering users_auth_graph. red_list=', red_list)
    cur=conn.cursor()
    times=[]
    successes=[]
    failures=[]
    try:
        section = configdb('report.ini', label)
        heading=section['title']     
        print('\t'+heading+' graph (timestamp='+str(datetime.now().time())+')')
        comment=section['comment']     
        whitelist=section['whitelist']     
        whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work
          
        f=plt.figure()
        plt.title(heading)
        plt.ylabel('authentications')
        plt.xlabel('time')
        plt.xticks(rotation=90)
        plt.grid(True)

        string=''
        for user in red_list:
            if user=='':
                break
            if string=='':
                string='\''+user+'\''
            else: 
                string=string+',\''+user+'\''
        if user=='':
            return      # Nothing in red_list - ie no graph
        count=0
        cmd="SELECT Auth_hour, username, COUNT(error_code) FILTER (WHERE error_code = 0) AS Success, COUNT(error_code) FILTER (WHERE error_code !=0) AS Failed FROM (SELECT date_trunc('hour', auth.timestamp) AS Auth_hour, username, error_code FROM auth WHERE username IN ({}) AND timestamp >= '{}' AND timestamp < '{}' AND username NOT IN ('{}')) tmp GROUP BY Auth_hour, username ORDER BY username, Auth_hour ASC".format(string,START,END,whitelist)
#        print(cmd)
        cur.execute(cmd)

            # row[0]    auth_hour
            # row[1]    username
            # row[2]    success
            # row[3]    fail

              # get start time
        t=datetime.strptime(START, '%Y-%m-%d')
        end=datetime.strptime(END, '%Y-%m-%d')
        # add timezone
        # as return from SQL includes timezone
        expect_time = t.replace(tzinfo=timezone('UTC'))
        end_time = end.replace(tzinfo=timezone('UTC'))
        row = cur.fetchone()
        username=row[1]
#        print('First endpoint=',username)
        while row is not None:
#            if DEBUG:
#                print('Row=',row,', expect_time=',expect_time)

                # Have we got another Username?
            if row[1]!=username:
#                print('Another endpoint=',username)

#                print('expect_time=',expect_time,' end_time=',end_time)
                    # Fill in any missing to end_time
                while expect_time<=end_time:
#                    print('end missing1 @', expect_time, 'got', timestamp)
                    times.append(expect_time)
                    successes.append(0)
                    failures.append(0)
                    expect_time = expect_time + timedelta(hours=1)

                    # Print graph for this endpoint
                if username=='':
                    name=''
                elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(username, ANON_USER_DIC, ANON_USER_NO, 'AnonUSER')
                else:
                    name=username
                hostname=name+' success'
#                print('Plot', hostname)
                x, = plt.plot(times, successes, label=hostname)
                x.set_label(hostname)
                hostname=name+' failed'
#                print('Plot', hostname)
                y, = plt.plot(times, failures, label=hostname)
                y.set_label(hostname)

                    # Move on to get the next device
                del times[:]
                del successes[:]
                del failures[:]
                expect_time = t.replace(tzinfo=timezone('UTC'))

                    # Update the username
                username = row[1]

            timestamp = row[0]
            success = row[2]
            failed = row[3]

                # Fill in any missing gaps
#            print('time=',timestamp,', expect=',expect_time)
            while timestamp > expect_time:
#                print('missing @', expect_time, 'got', timestamp)
                times.append(expect_time)
                successes.append(0)
                failures.append(0)
                expect_time = expect_time + timedelta(hours=1)

            times.append(timestamp)
            successes.append(success)
            failures.append(failed)
            expect_time = expect_time + timedelta(hours=1)
            row = cur.fetchone()

            # Fill in the last user's end
#        print('time=',timestamp,', expect=',expect_time)
        while expect_time<=end_time:
#            print('end missing @', expect_time, 'got', timestamp)
            times.append(expect_time)
            successes.append(0)
            failures.append(0)
            expect_time = expect_time + timedelta(hours=1)

            # Print last device graph
        if username=='':
            name=''
        elif ANON_USER:
            name,ANON_USER_NO=get_anonymous_name(username, ANON_USER_DIC, ANON_USER_NO, 'AnonUSER')
        else:
            name=username
        hostname=name+' success'
#        print('Plot', hostname)
        x, = plt.plot(times, successes, label=hostname)
        x.set_label(hostname)
        hostname=name+' failed'
#        print('Plot', hostname)
        y, = plt.plot(times, failures, label=hostname)
        y.set_label(hostname)
          

        plt.legend()
#        plt.show()
        
        FILE_INDEX+=1
        filename='graph'+str(FILE_INDEX)
        plt.savefig(filename, format='png', bbox_inches='tight')

            # WARNING I change the file name on each one as Linux 
            # seems to cache the first one and uses that!
            # OK a Linux flush might fix this but easier to 
            # just have unique graphs
        plt.clf()
        plt.close()

        pdf.image(filename, w=LAND_W, h=GRAPH_H, type='PNG')
        if os.path.exists(filename):
             os.remove(filename)
             
        if ANON_USER is False:
            if whitelist:
                pdf.cell(0, h, "User whitelist "+section['whitelist'], 0, 1, 'L')
                pdf.ln('')

        pdf.set_font("Arial", size = 11)
        pdf.multi_cell(0, H, comment, 0, 'L', False)
          
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        pdf.ln(h)
        if DEBUG:
            print('Leaving users_auth_graph')


############################################# 
# Create graph of wireless endpoint's burst auths per hour
def endpoints_wireless_burst_auth_graph(conn, pdf, red_list):

    global ANON_MAC
    global ANON_MAC_NO
    global ANON_MAC_DIC
    global FILE_INDEX

    if DEBUG:
        print('Entering endpoints_wireless_burst_auth_graph. red_list', red_list)
    cur=conn.cursor()
    times=[]
    successes=[]
    failures=[]
    try:
        section = configdb('report.ini', 'Top Wireless Burst Authentications per hour')
        heading=section['title']     
        print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
        comment=section['comment']     
        whitelist=section['whitelist']     
        whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work
          
        f=plt.figure()
        plt.title(heading)
        plt.ylabel('authentications')
        plt.xlabel('time')
        plt.xticks(rotation=90)
        plt.grid(True)

        string=''
        for mac in red_list:
            if mac=='':
                break   # nothing more in the red_list
            if string=='':
                string='\''+mac+'\''
            else: 
                string=string+',\''+mac+'\''
        if string=='':
            return      # nothing in the red_list, ie no graph
        count=0
        cmd="SELECT Auth_hour, mac, COUNT(error_code) FILTER (WHERE error_code = 0) AS Success, COUNT(error_code) FILTER (WHERE error_code !=0) AS Failed FROM (SELECT date_trunc('hour', auth.timestamp) AS Auth_hour, mac, error_code FROM auth WHERE mac IN ({}) AND timestamp >= '{}' AND timestamp < '{}' AND mac NOT IN ('{}')) tmp GROUP BY Auth_hour, mac ORDER BY mac, Auth_hour ASC".format(string,START,END,whitelist)
        print(cmd)
        cur.execute(cmd)

            # row[0]    auth_hour
            # row[1]    mac
            # row[2]    success
            # row[3]    fail

              # get start time
        t=datetime.strptime(START, '%Y-%m-%d')
        end=datetime.strptime(END, '%Y-%m-%d')
        # add timezone
        # as return from SQL includes timezone
        expect_time = t.replace(tzinfo=timezone('UTC'))
        end_time = end.replace(tzinfo=timezone('UTC'))
        row = cur.fetchone()
        mac=row[1]
#        print('First endpoint=',mac)
        while row is not None:
            if DEBUG:
                print('Row=',row,', expect_time=',expect_time)

                # Have we got another MAC address?
            if row[1]!=mac:
#                print('Another endpoint=',mac)

#                print('expect_time=',expect_time,' end_time=',end_time)
                    # Fill in any missing to end_time
                while expect_time<=end_time:
#                    print('end missing1 @', expect_time, 'got', timestamp)
                    times.append(expect_time)
                    successes.append(0)
                    failures.append(0)
                    expect_time = expect_time + timedelta(hours=1)

                    # Print graph for this endpoint
                if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
                else:
                    name=mac
                hostname=name+' success'
#                print('Plot', hostname)
                x, = plt.plot(times, successes, label=hostname)
                x.set_label(hostname)
                hostname=name+' failed'
#                print('Plot', hostname)
                y, = plt.plot(times, failures, label=hostname)
                y.set_label(hostname)

                    # Move on to get the next device
                del times[:]
                del successes[:]
                del failures[:]
                expect_time = t.replace(tzinfo=timezone('UTC'))

                    # Update the mac
                mac = row[1]

            timestamp = row[0]
            success = row[2]
            failed = row[3]

                # Fill in any missing gaps
#            print('time=',timestamp,', expect=',expect_time)
            while timestamp > expect_time:
#                print('missing @', expect_time, 'got', timestamp)
                times.append(expect_time)
                successes.append(0)
                failures.append(0)
                expect_time = expect_time + timedelta(hours=1)

            times.append(timestamp)
            successes.append(success)
            failures.append(failed)
            expect_time = expect_time + timedelta(hours=1)
            row = cur.fetchone()

        while expect_time<=end_time:
#            print('end missing @', expect_time, 'got', timestamp)
            times.append(expect_time)
            successes.append(0)
            failures.append(0)
            expect_time = expect_time + timedelta(hours=1)

            # Print last device graph
        if ANON_MAC:
            name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
        else:
            name=mac
        hostname=name+' success'
#        print('Plot', hostname)
        x, = plt.plot(times, successes, label=hostname)
        x.set_label(hostname)
        hostname=name+' failed'
#        print('Plot', hostname)
        y, = plt.plot(times, failures, label=hostname)
        y.set_label(hostname)
          

        plt.legend()
#        plt.show()
        
        FILE_INDEX+=1
        filename='graph'+str(FILE_INDEX)
        plt.savefig(filename, format='png', bbox_inches='tight')

            # WARNING I change the file name on each one as Linux 
            # seems to cache the first one and uses that!
            # OK a Linux flush might fix this but easier to 
            # just have unique graphs
        plt.clf()
        plt.close()

        pdf.image(filename, w=LAND_W, h=GRAPH_H, type='PNG')
        if os.path.exists(filename):
             os.remove(filename)
             
        if ANON_MAC is False:
            if whitelist:
                pdf.cell(0, h, "MAC whitelist "+section['whitelist'], 0, 1, 'L')
                pdf.ln('')

        pdf.set_font("Arial", size = 11)
        pdf.multi_cell(0, H, comment, 0, 'L', False)
          
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        pdf.ln(h)
        if DEBUG:
            print('Leaving endpoints_wireless_burst_auth_graph')


############################################# 
# Top Wireless Endpoints with most Auths
def wireless_endpoint_auths(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC

     red_list=[]
     if DEBUG:
        print('Entering wireless_endpoint_auths')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Wireless Endpoints Auths')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd = "SELECT count(*) AS total, count(*) FILTER (WHERE error_code=0), count(*) FILTER (WHERE error_code!=0), COALESCE(mac,'Null!') FROM auth WHERE nas_port_type='19' AND timestamp >= '{}' AND timestamp < '{}' AND mac NOT IN ('{}') GROUP BY auth.mac ORDER BY total DESC LIMIT 15".format(START,END,whitelist) 
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     success (value)
               # row[2]     failed (value)
               # row[3]     mac

          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(20, h, "Auths", 0, 0, 'L')
          pdf.cell(20, h, "Success", 0, 0, 'L')
          pdf.cell(20, h, "Failed", 0, 0, 'L')
          pdf.cell(30, h, "MAC", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                    print('Row=',row)
               pdf.set_fill_color(255,255,255)
               REVIEW['wireless_endpoint_auths']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    REVIEW['wireless_endpoint_auths']='High'
                    red_list.append(row[3])
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['wireless_endpoint_auths']!='High':
                         REVIEW['wireless_endpoint_auths']='Med'
               pdf.cell(30, H, "", 0, 0, 'L')
               pdf.cell(20, H, str(row[0]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[1]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[2]), 0, 0, 'L', True)
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(row[3], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=row[3]
               pdf.cell(30, H, name, 0, 1, 'L', True)
               row = cur.fetchone()

          pdf.ln('')
          if ANON_MAC is False:
            if whitelist:
               pdf.cell(0, h, "MAC whitelist "+section['whitelist'], 0, 1, 'L')
               pdf.ln('')

          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if DEBUG:
               print('Leaving wireless_endpoint_auths')
          return red_list


############################################# 
# Top Other Endpoints with most Auths
def virtual_user_auths(conn, pdf):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC
     global ANON_SERVICE
     global ANON_SERVICE_NO
     global ANON_SERVICE_DIC

     red_list=[]
     if DEBUG:
        print('Entering virtual_user_auths')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Virtual User Auths')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work
          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd = "SELECT count(*) AS total, count(*) FILTER(WHERE error_code=0), count(*) FILTER(WHERE error_code!=0), nas_port_type, COALESCE(username, 'Null!'), COALESCE(service,''), COALESCE(nads.name,''), nad_ip FROM auth JOIN nads ON auth.nad_ip = nads.ip WHERE nas_port_type NOT IN ('15','19') AND timestamp >= '{}' AND timestamp < '{}' AND auth.username NOT IN ('{}') GROUP BY nas_port_type, username, service, nads.name, nad_ip ORDER BY total DESC LIMIT 15".format(START,END,whitelist) 
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     success count (value)
               # row[2]     failed count (value)
               # row[3]     nas_port_type
               # row[4]     username
               # row[5]     service
               # row[6]     nads-name
               # row[7]     nad_ip

          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(15, h, "Auths", 0, 0, 'L')
          pdf.cell(20, h, "Success", 0, 0, 'L')
          pdf.cell(15, h, "Failed", 0, 0, 'L')
          pdf.cell(20, h, "Media", 0, 0, 'L')
          pdf.cell(50, h, "Username", 0, 0, 'L')
          pdf.cell(60, h, "Service", 0, 0, 'L')
          pdf.cell(45, h, "NAS Name", 0, 0, 'L')
          pdf.cell(30, h, "NAS IP", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               REVIEW['virtual_users_auth']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
          # NOTE adding username as unlikely to have a MAC address
                    if row[4] not in red_list:      # Only add unique users!!!
                        red_list.append(row[4])
                    REVIEW['virtual_users_auth']='High'
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['virtual_users_auth']!='High':
                         REVIEW['virtual_users_auth']='Med'
               if row[3] == '5':
                    label='Other'
               else:
                    label=row[3]
                    pdf.set_fill_color(255,0,0)
                    print('What media is this=',label)
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[1]), 0, 0, 'L', True)
               pdf.cell(15, H, str(row[2]), 0, 0, 'L', True)
               pdf.cell(20, H, label, 0, 0, 'L', True)
               if row[4]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[4], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[4]
               pdf.cell(50, H, name, 0, 0, 'L', True)
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[5], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[5]
               pdf.cell(60, H, name, 0, 0, 'L', True)
               if ANON_NAS:
                    name,ANON_NAS_NO=get_anonymous_name(row[7], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                    name2=name
               else:
                    name=row[6]
                    name2=row[7]
               pdf.cell(45, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, name2, 0, 1, 'L', True)
               row = cur.fetchone()

          pdf.ln('')
          if ANON_USER is False:
            if whitelist:
               pdf.cell(0, h, "Username whitelist "+section['whitelist'], 0, 1, 'L')
               pdf.ln('')
          
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)

          if DEBUG:
               print('Leaving virtual_user_auths')
          return red_list


############################################# 
# Top Other Endpoints with most Auths in a an hour
def virtual_user_auths_burst(conn, pdf, done_list):

     red_list=[]

     if DEBUG:
        print('Entering virtual_user_auths_burst, done_list=',done_list)
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Virtual Burst Authentications per hour')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          red_threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work

          amber_threshold=red_threshold*2//3
          
          cmd = "SELECT count(*) AS total, COALESCE(username,'Null!') AS username FROM (SELECT date_trunc('hour',auth.timestamp) AS Auth_hour, username FROM auth WHERE nas_port_type NOT IN ('15','19') AND timestamp >= '{}' AND timestamp < '{}' AND username NOT IN ('{}')) tmp GROUP BY auth_hour, username ORDER BY total DESC".format(START,END,whitelist) 
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     username

               # This SQL is suboptimal and is not returning unique 
               # list of MAC addresses. To address this I use the 
               # python to return the worst MAC addresses
               # Sure this is not great python but should work ;-)
          row = cur.fetchone()
          count=0
          while row is not None: 
               if DEBUG:
                    print('Row=',row)
               if row[0]>red_threshold:
                        # Only first 3 previous one examined in details
                   if row[1] not in done_list:
                       if row[1] not in red_list:
                            red_list.append(row[1])
                            count+=1
                                # Only record first 3 worst offenders
                            if count >= 3:
                                break
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if len(red_list)==0:
               pdf.ln(h)
          if DEBUG:
                print('Leaving virtual_user_auths_burst, red_list=',red_list)
          return red_list


############################################# 
# Wired Endpoint details
def wired_endpoint_details(conn, pdf, mac):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC
     global ANON_SERVICE
     global ANON_SERVICE_NO
     global ANON_SERVICE_DIC

     if DEBUG:
         print('Entering wired_endpoint_details, MAC: ',mac)
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Wired Endpoints Auths')
          print('\t\t'+mac+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd = "SELECT count(*) AS total, cppm_error_codes.error_code_str, COALESCE(auth.username,''), COALESCE(auth.service, ''), COALESCE(nads.name,''), COALESCE(auth.nad_ip,''), COALESCE(auth.nas_port_id, '') FROM auth JOIN nads ON auth.nad_ip = nads.ip JOIN cppm_error_codes ON auth.error_code = cppm_error_codes.error_code WHERE auth.mac='{}' AND timestamp >= '{}' AND timestamp < '{}' GROUP BY cppm_error_codes.error_code_str, auth.username, auth.service, nads.name, auth.nad_ip, auth.nas_port_id ORDER BY total DESC LIMIT 10".format(mac,START,END) 
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     error_str
               # row[2]     username
               # row[3]     service
               # row[4]     switch name
               # row[5]     switch IP
               # row[6]     Port

          pdf.set_font("Arial", 'B', size = 14)
          name=mac
          if ANON_MAC:
              name=ANON_MAC_DIC[mac]
          value="MAC \'"+name+"\' Authentication Details"
          pdf.cell(0, h, value, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(15, h, "Auths", 0, 0, 'L')
          pdf.cell(50, h, "Error", 0, 0, 'L')
          pdf.cell(40, h, "Username", 0, 0, 'L')
          pdf.cell(50, h, "Service", 0, 0, 'L')
          pdf.cell(35, h, "Switch Name", 0, 0, 'L')
          pdf.cell(30, h, "Switch IP", 0, 0, 'L')
          pdf.cell(40, h, "Switch Port", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               pdf.cell(50, H, row[1], 0, 0, 'L', True)
               value=normalize_mac(row[2])
               if row[2]=='':
                   name=''
               elif value==mac:
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[2], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[2]
               pdf.cell(40, H, name, 0, 0, 'L', True)
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[3], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[3]
               pdf.cell(50, H, name, 0, 0, 'L', True)
               if ANON_NAS:
                    name,ANON_NAS_NO=get_anonymous_name(row[5], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                    name2=name
               else:
                    name=row[4]
                    name2=row[5]
               pdf.cell(35, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, name2, 0, 0, 'L', True)
               pdf.cell(40, H, row[6], 0, 1, 'L', True)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if DEBUG:
              print('Leaving wired_endpoint_details')



############################################# 
# Wireless Endpoint details
def wireless_endpoint_details(conn, pdf, mac):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC
     global ANON_SERVICE
     global ANON_SERVICE_NO
     global ANON_SERVICE_DIC

     if DEBUG:
         print('Entering wireless_endpoint_details, MAC: ', mac)
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Wireless Endpoints Auths')
          print('\t\t'+mac+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10

          cmd = "SELECT count(*) AS total, cppm_error_codes.error_code_str, COALESCE(auth.username,''), COALESCE(auth.service, ''), COALESCE(nads.name,''), COALESCE(auth.nad_ip,''), COALESCE(auth.ssid,'') FROM auth JOIN nads ON auth.nad_ip = nads.ip JOIN cppm_error_codes ON auth.error_code = cppm_error_codes.error_code WHERE auth.mac='{}' AND timestamp >= '{}' AND timestamp < '{}' GROUP BY cppm_error_codes.error_code_str, auth.username, auth.service, nads.name, auth.nad_ip, auth.ssid ORDER BY total DESC LIMIT 10".format(mac,START,END) 
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     error_str
               # row[2]     username
               # row[3]     service
               # row[4]     NAS name
               # row[5]     NAS IP
               # row[6]     SSID

          pdf.set_font("Arial", 'B', size = 14)
          name=mac
          if ANON_MAC:
                 name=ANON_MAC_DIC[mac]
          value="MAC \'"+name+"\' Authentication Details"
          pdf.cell(0, h, value, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(15, h, "Auths", 0, 0, 'L')
          pdf.cell(45, h, "Error", 0, 0, 'L')
          pdf.cell(50, h, "Username", 0, 0, 'L')
          pdf.cell(60, h, "Service", 0, 0, 'L')
          pdf.cell(40, h, "NAS Name", 0, 0, 'L')
          pdf.cell(30, h, "NAS IP", 0, 0, 'L')
          pdf.cell(20, h, "SSID", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                    print('Row=',row)
               pdf.set_fill_color(255,255,255)
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               pdf.cell(45, H, row[1], 0, 0, 'L', True)
               value=normalize_mac(row[2])
               if row[2]=='':
                   name=''
               elif value==mac:
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[2], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[2]
               pdf.cell(50, H, name, 0, 0, 'L', True)
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[3], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[3]
               pdf.cell(60, H, name, 0, 0, 'L', True)
               if ANON_NAS:
                    name,ANON_NAS_NO=get_anonymous_name(row[5], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                    name2=name
               else:
                    name=row[4]
                    name2=row[5]
               pdf.cell(40, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, name2, 0, 0, 'L', True)
               pdf.cell(20, H, row[6], 0, 1, 'L', True)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if DEBUG:
              print('Leaving wireless_endpoint_details')


############################################# 
# Other Endpoint details
def virtual_user_details(conn, pdf, username):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC
     global ANON_SERVICE
     global ANON_SERVICE_NO
     global ANON_SERVICE_DIC

     if DEBUG:
        print('Entering virtual_user_details, username: ', username)
     cur = conn.cursor()
     try:
          cmd = "SELECT count(*) AS total, cppm_error_codes.error_code_str, COALESCE(auth.service, ''), COALESCE(nads.name,''), COALESCE(auth.nad_ip,'') FROM auth JOIN nads ON auth.nad_ip = nads.ip JOIN cppm_error_codes ON auth.error_code = cppm_error_codes.error_code WHERE auth.username='{}' AND timestamp >= '{}' AND timestamp < '{}' GROUP BY cppm_error_codes.error_code_str, auth.service, nads.name, auth.nad_ip ORDER BY total DESC LIMIT 15".format(username,START,END) 
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     error_str
               # row[2]     service
               # row[3]     switch name
               # row[4]     switch IP

          pdf.set_font("Arial", 'B', size = 14)
          if ANON_USER:
               name=ANON_USER_DIC[username]
          else: 
              name=username
          value="Username \'"+name+"\' Authentication Details"
          if DEBUG:
              print('Display name=',value)
          pdf.cell(0, h, value, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(15, h, "Auths", 0, 0, 'L')
          pdf.cell(45, h, "Error", 0, 0, 'L')
          pdf.cell(100, h, "Service", 0, 0, 'L')
          pdf.cell(50, h, "NAS Name", 0, 0, 'L')
          pdf.cell(30, h, "NAS IP", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                    print('Row=',row)
               pdf.set_fill_color(255,255,255)
#               if row[0] > red_threshold:
#                    pdf.set_fill_color(255,0,0)
#               elif row[0] > amber_threshold:
#                    pdf.set_fill_color(255,194,0)
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               pdf.cell(45, H, row[1], 0, 0, 'L', True)
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[2], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[2]
               pdf.cell(100, H, name, 0, 0, 'L', True)
               if ANON_NAS:
                    name,ANON_NAS_NO=get_anonymous_name(row[4], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                    name2=name
               else:
                    name=row[3]
                    name2=row[4]
               pdf.cell(50, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, name2, 0, 1, 'L', True)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if DEBUG:
            print('Leaving virtual_user_details')


############################################# 
# Top 802.1X User Auths (success+fail)
def dot1x_auths(conn, pdf):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     red_list =[]
     if DEBUG:
        print('Entering dot1x_auths')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top 802.1X Users')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd = "SELECT count(auth.error_code) AS auths, count(*) FILTER (WHERE error_code=0), count(*) FILTER (WHERE error_code!=0), auth.username FROM auth WHERE timestamp >= '{}' AND timestamp < '{}' AND auth_method ILIKE 'EAP-%' AND auth.username NOT IN ('{}') GROUP BY auth.username ORDER BY auths DESC LIMIT 15".format(START,END,whitelist)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     success count (value)
               # row[2]     failed count (value)
               # row[3]     user

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(20, h, "Auths", 0, 0, 'L')
          pdf.cell(20, h, "Success", 0, 0, 'L')
          pdf.cell(20, h, "Failed", 0, 0, 'L')
          pdf.cell(45, h, "User", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                    print('Row=',row)
               pdf.set_fill_color(255,255,255)
               REVIEW['dot1x_auths']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[3])
                    REVIEW['dot1x_auths']='High'
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['dot1x_auths']!='High':
                         REVIEW['dot1x_auths']='Med'
               pdf.cell(30, H, "", 0, 0, 'L')
               pdf.cell(20, H, str(row[0]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[1]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[2]), 0, 0, 'L', True)
               if row[3]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[3], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[3]
               pdf.cell(45, H, name, 0, 1, 'L', True)
               row = cur.fetchone()

          pdf.ln('')
          if ANON_USER is False:
            if whitelist:
               pdf.cell(0, h, "Username whitelist "+section['whitelist'], 0, 1, 'L')
               pdf.ln('')
          
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if len(red_list)==0:
               pdf.ln(h)
          if DEBUG:
             print('Leaving dot1x_auths')
          return red_list


############################################# 
# Top NAS Most Auths (success+fail)
def nas_most_auths(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC

     red_list =[]
     if DEBUG:
         print('Entering nas_auths')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top NAS with Most Authentications')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
#          cmd = "SELECT count(*) AS total, count(*) FILTER (WHERE error_code=0), count(*) FILTER (WHERE error_code!=0), COALESCE(nads.name,''), COALESCE(nad_ip, nas_identifier, 'Unknown') AS nas_ip, nas_port_type FROM auth LEFT JOIN nads ON nads.ip = auth.nad_ip WHERE timestamp >= '{}' AND timestamp < '{}' AND auth.nad_ip NOT IN ('{}') GROUP BY nads.name, nas_identifier, nad_ip, nas_port_type ORDER BY nas_port_type ASC, total DESC LIMIT 15".format(START,END,whitelist)
          cmd = "SELECT count(*) AS total, count(*) FILTER (WHERE error_code=0), count(*) FILTER (WHERE error_code!=0), COALESCE(nads.name,''), COALESCE(nad_ip, 'Unknown') AS nas_ip, nas_port_type, COALESCE(nas_identifier,''), COALESCE(called_station_id,'') FROM auth LEFT JOIN nads ON nads.ip = auth.nad_ip WHERE timestamp >= '{}' AND timestamp < '{}' AND auth.nad_ip NOT IN ('{}') GROUP BY nads.name, nas_identifier, nad_ip, nas_port_type, called_station_id ORDER BY nas_port_type ASC, total DESC LIMIT 15".format(START,END,whitelist)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     success count (value)
               # row[2]     failed count (value)
               # row[3]     NAS Name
               # row[4]     NAS IP
               # row[5]     Media
               # row[6]     NAS Identifier
               # row[7]     NAS MAC

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(20, h, "Media", 0, 0, 'L')
          pdf.cell(20, h, "Auths", 0, 0, 'L')
          pdf.cell(20, h, "Success", 0, 0, 'L')
          pdf.cell(20, h, "Failed", 0, 0, 'L')
          pdf.cell(45, h, "NAS Name", 0, 0, 'L')
          pdf.cell(30, h, "NAS IP", 0, 0, 'L')
          pdf.cell(30, h, "NAS Identifier", 0, 0, 'L')
          pdf.cell(40, h, "NAS MAC", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               REVIEW['nas_auths']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[5])
                    REVIEW['nas_auths']='High'
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['nas_auths']!='High':
                         REVIEW['nas_auths']='Med'
               if row[5]=='5':
                    label='Other'
               elif row[5]=='15':
                    label='Wired'
               elif row[5]=='19':
                    label='Wifi'
               else:
                    label=row[5]
               pdf.cell(20, H, label, 0, 0, 'L', True)
               pdf.cell(20, H, str(row[0]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[1]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[2]), 0, 0, 'L', True)
               mac=normalize_mac(row[7])
               if ANON_NAS:
                    name,ANON_NAS_NO=get_anonymous_name(row[4], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                    name2=name
                    name3=name
               else:
                    name=row[3]
                    name2=row[4]
                    name3=row[6]
               pdf.cell(45, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, name2, 0, 0, 'L', True)
               pdf.cell(30, H, name3, 0, 0, 'L', True)
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=mac
               pdf.cell(40, H, name, 0, 1, 'L', True)
               row = cur.fetchone()

          pdf.ln('')
          if ANON_NAS is False:
            if whitelist:
               pdf.cell(0, H, "NAD whitelist "+section['whitelist'], 0, 1, 'L')
               pdf.ln('')

          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving nas_auths')
          return red_list


############################################# 
# Top NAS Least Auths (success+fail)
def nas_least_auths(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC

     if DEBUG:
         print('Entering nas_least_auths')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top NAS with Least Authentications')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work

#          cmd = "SELECT count(*) AS total, count(*) FILTER (WHERE error_code=0), count(*) FILTER (WHERE error_code!=0), COALESCE(nads.name,''), COALESCE(nad_ip, 'Unknown') AS nas_ip, nas_port_type, nas_identifier FROM auth LEFT JOIN nads ON nads.ip = auth.nad_ip WHERE timestamp >= '{}' AND timestamp < '{}' AND auth.nad_ip NOT IN ('{}') GROUP BY nads.name, nas_identifier, nad_ip, nas_port_type ORDER BY nas_port_type ASC, total ASC LIMIT 10".format(START,END,whitelist)
          cmd = "SELECT count(*) AS total, count(*) FILTER (WHERE error_code=0), count(*) FILTER (WHERE error_code!=0), COALESCE(nads.name,''), COALESCE(nad_ip, 'Unknown') AS nas_ip, nas_port_type, COALESCE(nas_identifier,''), COALESCE(called_station_id,'') FROM auth LEFT JOIN nads ON nads.ip = auth.nad_ip WHERE timestamp >= '{}' AND timestamp < '{}' AND auth.nad_ip NOT IN ('{}') GROUP BY nads.name, nas_identifier, nad_ip, nas_port_type, called_station_id ORDER BY nas_port_type ASC, total ASC LIMIT 15".format(START,END,whitelist)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     success count (value)
               # row[2]     failed count (value)
               # row[3]     NAS Name
               # row[4]     NAS IP
               # row[5]     Media

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(20, h, "Media", 0, 0, 'L')
          pdf.cell(20, h, "Auths", 0, 0, 'L')
          pdf.cell(20, h, "Success", 0, 0, 'L')
          pdf.cell(20, h, "Failed", 0, 0, 'L')
          pdf.cell(45, h, "NAS Name", 0, 0, 'L')
          pdf.cell(30, h, "NAS IP", 0, 0, 'L')
          pdf.cell(30, h, "NAS Identifier", 0, 0, 'L')
          pdf.cell(40, h, "NAS MAC", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               if row[5]=='5':
                    label='Other'
               elif row[5]=='15':
                    label='Wired'
               elif row[5]=='19':
                    label='Wifi'
               else:
                    label=row[5]
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[4])
               pdf.cell(20, H, label, 0, 0, 'L', True)
               pdf.cell(20, H, str(row[0]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[1]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[2]), 0, 0, 'L', True)
               if ANON_NAS:
                    name,ANON_NAS_NO=get_anonymous_name(row[4], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                    name2=name
                    name3=name
               else:
                    name=row[3]
                    name2=row[4]
                    name3=row[6]
               pdf.cell(45, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, name2, 0, 0, 'L', True)
               pdf.cell(30, H, name3, 0, 0, 'L', True)
               mac=normalize_mac(row[7])
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                   name=mac
               pdf.cell(40, H, name, 0, 1, 'L', True)
               row = cur.fetchone()

          pdf.ln('')
          if ANON_NAS is False:
            if whitelist:
               pdf.cell(0, H, "NAD whitelist "+section['whitelist'], 0, 1, 'L')
               pdf.ln('')

          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
            print('Leaving nas_least_auths')


############################################# 
# Top 802.1X Devices with multiple users
def dot1x_device_multi_users(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC

     red_list =[]
     if DEBUG:
         print('Entering dot1x_device_multi_users')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top 802.1X Devices with Multiple Users')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd="SELECT count(*) AS Users, mac FROM (SELECT username, mac FROM auth WHERE timestamp >= '{}' AND timestamp < '{}' AND auth_status='User' AND auth_method ILIKE 'EAP-%' AND mac NOT IN ('{}') GROUP BY username, mac ORDER BY mac) t GROUP BY mac ORDER BY users DESC, mac ASC LIMIT 10".format(START,END,whitelist)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     mac

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(15, h, "Users", 0, 0, 'L')
          pdf.cell(30, h, "MAC", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          
          if row is None:
               pdf.cell(0, H, "No devices found!", 0, 1, 'L')
               pdf.ln('')
               return red_list

          if row[0] == 1:          # Only 1 entry
               pdf.cell(0, H, "No shared devices found", 0, 1, 'L')
               pdf.ln('')
               return red_list
               
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               if row[0] == 1:          # Only 1 entry
                    break
               pdf.set_fill_color(255,255,255)
               REVIEW['dotx1_device_multi_users']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[1])
                    REVIEW['dotx1_device_multi_users']='High'
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['dotx1_device_multi_users']!='High':
                         REVIEW['dotx1_device_multi_users']='Med'
               pdf.cell(30, H, "", 0, 0, 'L')
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(row[1], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=row[1]
               pdf.cell(30, H, name, 0, 1, 'L', True)
               row = cur.fetchone()

          pdf.ln('')
          if ANON_MAC is False:
            if whitelist:
               pdf.cell(0, h, "Device whitelist "+section['whitelist'], 0, 1, 'L')
               pdf.ln('')
          
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if len(red_list)==0:
               pdf.ln(h)
          if DEBUG:
              print('Leaving dot1x_device_multi_users')
          return red_list


############################################# 
# Top 802.1X Devices with multiple users detail
def dot1x_device_multi_users_detail(conn, pdf, mac):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     if DEBUG:
         print('Entering dot1x_device_multi_users_detail, MAC: ',mac)
     cur = conn.cursor()
     try:
          cmd="SELECT count(*) AS auths, username, service, nas_port_type FROM public.auth WHERE timestamp >= '{}' AND timestamp < '{}' AND auth.auth_status='User' AND auth_method ILIKE 'EAP-%' AND auth.mac ='{}' GROUP BY username, service, nas_port_type ORDER BY auths DESC LIMIT 10".format(START,END, mac)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     user
               # row[2]     service
               # row[3]     media

          pdf.set_font("Arial", 'B', size = 14)
          value="MAC \'"+mac+"\' associated users"
          pdf.cell(0, h, value, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(15, h, "Users", 0, 0, 'L')
          pdf.cell(45, h, "User", 0, 0, 'L')
          pdf.cell(45, h, "Service", 0, 0, 'L')
          pdf.cell(20, h, "Media", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               pdf.cell(30, H, "", 0, 0, 'L')
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               if row[1]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[1], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[1]
               pdf.cell(45, H, name, 0, 0, 'L', True)
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[2], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[2]
               pdf.cell(45, H, name, 0, 0, 'L', True)
               if row[3]=='5':
                    label = 'Other'
               elif row[3]=='15':
                    label = 'Wired'
               elif row[3]=='19':
                    label = 'Wifi'
               else: 
                    label = row[3]
                    pdf.set_fill_color(255,0,0)
               pdf.cell(20, H, label, 0, 1, 'L', True)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if DEBUG:
              print('Leaving dot1x_device_multi_users_detail')


############################################# 
# Top 802.1X User with multiple devices
def dot1x_user_multi_devices(conn, pdf):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     red_list =[]
     if DEBUG:
         print('Entering dot1x_user_multi_devices')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top 802.1X Users with Multiple Devices')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd="SELECT count(*) AS Users, username FROM (SELECT username, mac FROM auth WHERE timestamp >= '{}' AND timestamp < '{}' AND auth_status='User' AND auth_method ILIKE 'EAP-%' AND username NOT IN ('{}') GROUP BY username, mac ORDER BY mac) t GROUP BY username ORDER BY users DESC LIMIT 10".format(START,END,whitelist)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     username

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(20, h, "Devices", 0, 0, 'L')
          pdf.cell(50, h, "Username", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()

          if row is None:
               pdf.cell(0, H, "No users found", 0, 1, 'L')
               pdf.ln('')
               return red_list

          if row[0] == 1:          # Only 1 entry
               pdf.cell(0, H, "No users with multiple devices found", 0, 1, 'L')
               return red_list
               

          while row is not None:
               if DEBUG:
                   print('Row=',row)
               if row[0] == 1:          # Only 1 entry
                    break
               pdf.set_fill_color(255,255,255)
               REVIEW['dot1x_user_multi_devices']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[1])
                    REVIEW['dot1x_user_multi_devices']='High'
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['dot1x_user_multi_devices']!='High':
                         REVIEW['dot1x_user_multi_devices']='Med'
               red_list.append(row[1])
               pdf.cell(30, H, "", 0, 0, 'L')
               pdf.cell(20, H, str(row[0]), 0, 0, 'L', True)
               if row[1]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[1], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[1]
               pdf.cell(50, H, name, 0, 1, 'L', True)
               row = cur.fetchone()

          pdf.ln('')
          if ANON_USER is False:
            if whitelist:
               pdf.cell(0, h, "Username whitelist "+section['whitelist'], 0, 1, 'L')
               pdf.ln('')
          
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if len(red_list)==0:
               pdf.ln(h)
          if DEBUG:
              print('Leaving dot1x_user_multi_devices')
          return red_list


############################################# 
# Top 802.1X Users with multiple devices detail
def dot1x_user_multi_devices_detail(conn, pdf, user):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC

     if DEBUG:
         print('Entering dot1x_user_multi_devices_detail, user:',user)
     cur = conn.cursor()
     try:
          cmd="SELECT count(*) AS auths, mac, service, nas_port_type FROM auth WHERE timestamp >= '{}' AND timestamp < '{}' AND auth.auth_status='User' AND auth_method ILIKE 'EAP-%' AND auth.username ='{}' GROUP BY mac, service, nas_port_type ORDER BY auths DESC LIMIT 10".format(START,END, user)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     MAC
               # row[2]     service
               # row[3]     media

          pdf.set_font("Arial", 'B', size = 14)
          value="Username \'"+user+"\' associated devices"
          pdf.cell(0, h, value, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(15, h, "Auths", 0, 0, 'L')
          pdf.cell(45, h, "MAC", 0, 0, 'L')
          pdf.cell(75, h, "Service", 0, 0, 'L')
          pdf.cell(20, h, "Media", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()

          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.cell(30, H, "", 0, 0, 'L')
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(row[1], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=row[1]
               pdf.cell(45, H, name, 0, 0, 'L', True)
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[2], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[2]
               pdf.cell(75, H, name, 0, 0, 'L', True)
               if row[3]=='5':
                    label = 'Other'
               elif row[3]=='15':
                    label = 'Wired'
               elif row[3]=='19':
                    label = 'Wifi'
               else: 
                    label = row[3]
                    pdf.set_fill_color(255,0,0)
               pdf.cell(20, H, label, 0, 1, 'L', True)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if DEBUG:
              print('Leaving dot1x_user_multi_devices_detail')


############################################# 
# Top Wired Device Moves 
def wired_device_moves(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC

     red_list =[]
     if DEBUG:
         print('Entering wired_device_moves')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Wired Devices that have Moved')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd="SELECT count(mac) AS moves, mac FROM (SELECT mac FROM auth WHERE timestamp >= '{}' AND timestamp < '{}' AND nas_port_type='15' AND mac NOT IN ('{}') GROUP BY nad_ip, nas_identifier, nas_port_id, mac ORDER BY mac) t GROUP BY mac ORDER BY moves DESC, mac ASC LIMIT 10".format(START,END,whitelist)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     mac

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(15, h, "Moves", 0, 0, 'L')
          pdf.cell(30, h, "MAC", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()

          if row is None: 
               pdf.cell(0, h, "No wired devices!!!", 0, 1, 'L')
               return red_list

          if row[0] == 1:          # Only 1 entry
               pdf.cell(0, h, "No wired devices moved", 0, 1, 'L')
               return red_list

          while row is not None:
               if DEBUG:
                   print('Row=',row)
               if row[0] == 1:          # Only 1 entry
                    break
               pdf.set_fill_color(255,255,255)
               REVIEW['wired_device_moves']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    REVIEW['wired_device_moves']='High'
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['wired_device_moves']!='High':
                         REVIEW['wired_device_moves']='Med'
               red_list.append(row[1])
               pdf.cell(30, H, "", 0, 0, 'L')
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(row[1], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=row[1]
               pdf.cell(30, H, name, 0, 1, 'L', True)
               row = cur.fetchone()

          pdf.ln('')
          if ANON_MAC is False:
            if whitelist:
               pdf.cell(0, h, "Device whitelist "+section['whitelist'], 0, 1, 'L')
               pdf.ln('')
          
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if len(red_list)==0:
               pdf.ln(h)
          if DEBUG:
              print('Leaving wired_device_moves')
          return red_list


############################################# 
# Top Wired Device Moves details
def wired_device_moves_details(conn, pdf, mac):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC

     if DEBUG:
         print('Entering wired_device_moves_details, MAC: ',mac)
     cur = conn.cursor()
     try:
          cmd="SELECT nads.name, nad_ip, nas_port_id, service, auth_status, auth_method, username FROM auth JOIN nads ON auth.nad_ip = nads.ip WHERE timestamp >= '{}' AND timestamp < '{}' AND nas_port_type='15' AND mac='{}' GROUP BY nads.name, nad_ip, nas_port_id, service, auth_status, username, auth_method LIMIT 10".format(START,END, mac)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     Switch name
               # row[1]     Switch IP
               # row[2]     Switch port
               # row[3]     Service
               # row[4]     Auth Status
               # row[5]     Method
               # row[6]     Username

          pdf.set_font("Arial", 'B', size = 14)
          value="MAC \'"+mac+"\' associated ports and users"
          pdf.cell(0, h, value, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "Switch", 0, 0, 'L')
          pdf.cell(25, h, "Switch IP", 0, 0, 'L')
          pdf.cell(45, h, "Port", 0, 0, 'L')
          pdf.cell(80, h, "Service", 0, 0, 'L')
          pdf.cell(15, h, "Type", 0, 0, 'L')
          pdf.cell(35, h, "Method", 0, 0, 'L')
          pdf.cell(45, h, "Username", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               if ANON_NAS:
                    name,ANON_NAS_NO=get_anonymous_name(row[1], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                    name2=name
               else:
                    name=row[0]
                    name2=row[1]
               pdf.cell(30, H, name, 0, 0, 'L', True)
               pdf.cell(25, H, name2, 0, 0, 'L', True)
               pdf.cell(45, H, row[2], 0, 0, 'L', True)
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[3], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[3]
               pdf.cell(80, H, name, 0, 0, 'L', True)
               pdf.cell(15, H, row[4], 0, 0, 'L', True)
               pdf.cell(35, H, row[5], 0, 0, 'L', True)
               if row[6]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[6], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[6]
               pdf.cell(45, H, name, 0, 1, 'L', True)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if DEBUG:
              print('Leaving wired_device_moves_details')
          return red_list


############################################# 
# Top Wifi Device SSID Moves 
def wifi_device_ssid_moves(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC

     red_list =[]
     if DEBUG:
         print('Entering wifi_device_ssid_moves')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Wireless Devices with Multiple SSID')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd="SELECT count(mac) AS moves, mac FROM (SELECT mac FROM auth WHERE timestamp >= '{}' AND timestamp < '{}' AND nas_port_type='19' AND auth_status!='Failed' AND mac NOT IN ('{}') GROUP BY mac, ssid) t GROUP BY mac ORDER BY moves DESC, mac ASC LIMIT 10".format(START,END,whitelist)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count (value)
               # row[1]     mac

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(45, h, "SSID moves", 0, 0, 'L')
          pdf.cell(30, h, "MAC", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()

          if row is None:      
               pdf.cell(0, h, "No wireless device!!!", 0, 1, 'L')
               pdf.ln('')
               return red_list

          if row[0] == 1:          # Only 1 entry
               pdf.cell(0, h, "No wireless device on multiple SSIDs", 0, 1, 'L')
               pdf.ln('')
               return red_list

          while row is not None:
               if DEBUG:
                   print('Row=',row)
               if row[0] == 1:          # Only 1 entry
                    break
               pdf.set_fill_color(255,255,255)
               REVIEW['wireless_device_ssid_moves']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    REVIEW['wireless_device_ssid_moves']='High'
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['wireless_device_ssid_moves']!='High':
                         REVIEW['wireless_device_ssid_moves']='Med'
               red_list.append(row[1])
               pdf.cell(30, H, "", 0, 0, 'L')
               pdf.cell(45, H, str(row[0]), 0, 0, 'L', True)
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(row[1], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=row[1]
               pdf.cell(30, H, name, 0, 1, 'L', True)
               row = cur.fetchone()

          pdf.ln('')
          if ANON_MAC is False:
            if whitelist:
               pdf.cell(0, h, "Username whitelist "+section['whitelist'], 0, 1, 'L')
               pdf.ln('')
          
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if len(red_list)==0:
               pdf.ln(h)
          if DEBUG:
              print('Leaving wifi_device_ssid_moves')
          return red_list


############################################# 
# Top Wifi Device SSID Moves Details
def wifi_device_ssid_moves_details(conn, pdf, mac):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC

     if DEBUG:
         print('Entering wifi_device_ssid_moves_details, MAC: ',mac)
     cur = conn.cursor()
     try:
          cmd="SELECT nads.name, nad_ip, ssid, COALESCE(service,''), auth_status, COALESCE(auth_method,''), username FROM auth JOIN nads ON auth.nad_ip = nads.ip WHERE timestamp >= '{}' AND timestamp < '{}' AND auth.nas_port_type='19' AND mac='{}' GROUP BY nads.name, nad_ip, ssid, service, auth_status, username, auth_method LIMIT 10".format(START,END, mac)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     NAS name
               # row[1]     NAS IP
               # row[2]     SSID
               # row[3]     Service
               # row[4]     Auth Status
               # row[5]     Method
               # row[6]     Username

          pdf.set_font("Arial", 'B', size = 14)
          value="MAC \'"+mac+"\' associated SSID and users"
          pdf.cell(0, h, value, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(45, h, "NAS", 0, 0, 'L')
          pdf.cell(25, h, "NAS IP", 0, 0, 'L')
          pdf.cell(25, h, "SSID", 0, 0, 'L')
          pdf.cell(80, h, "Service", 0, 0, 'L')
          pdf.cell(25, h, "Auth Status", 0, 0, 'L')
          pdf.cell(40, h, "Method", 0, 0, 'L')
          pdf.cell(45, h, "Username", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               if ANON_NAS:
                    name,ANON_NAS_NO=get_anonymous_name(row[1], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                    name2=name
               else:
                    name=row[0]
                    name2=row[1]
               pdf.cell(45, H, name, 0, 0, 'L', True)
               pdf.cell(25, H, name2, 0, 0, 'L', True)
               pdf.cell(25, H, row[2], 0, 0, 'L', True)
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[3], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[3]
               pdf.cell(80, H, name, 0, 0, 'L', True)
               pdf.cell(25, H, row[4], 0, 0, 'L', True)
               pdf.cell(40, H, row[5], 0, 0, 'L', True)
               if row[6]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[6], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[6]
               pdf.cell(45, H, name, 0, 1, 'L', True)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if DEBUG:
              print('Leaving wifi_device_ssid_moves_details')


############################################# 
# Top Auths Failed by Policy
def failed_authorization(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC
     global ANON_SERVICE
     global ANON_SERVICE_NO
     global ANON_SERVICE_DIC

     red_list =[]
     if DEBUG:
         print('Entering failed_authorization')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Failed Authorization')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist_mac=section['whitelist_mac']     
          whitelist_mac=whitelist_mac.replace(",","','")     # replace the coma with ',' so that SQL will work
          whitelist_user=section['whitelist_user']     
          whitelist_user=whitelist_user.replace(",","','")     # replace the coma with ',' so that SQL will work

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd="SELECT count(*) AS totals, auth_username, COALESCE(mac,''), nas_port_type, COALESCE(nads.name,''), COALESCE(nad_ip,nas_identifier,''), COALESCE(ssid,''), COALESCE(called_station_id,''), COALESCE(nas_port_id,''), COALESCE(service,''), COALESCE(auth_method,'') FROM auth LEFT JOIN nads ON auth.nad_ip = nads.ip WHERE timestamp >= '{}' AND timestamp < '{}' AND error_code=206 AND (mac NOT IN ('{}') OR auth_username NOT IN ('{}')) GROUP BY auth_username, mac, nas_port_type, nads.name, nad_ip, nas_identifier, called_station_id, nas_port_id, ssid, service, auth_method ORDER BY totals DESC LIMIT 15".format(START,END,whitelist_mac,whitelist_user)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     count(int)
               # row[1]     username
               # row[2]     mac
               # row[3]     Media
               # row[4]     NAD name
               # row[5]     NAD IP
               # row[6]     SSID
               # row[7]     Called Station has Cisco SSID 
               # row[8]     Switch port
               # row[9]     Service
               # row[10]     Auth method

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(15, h, "Authz", 0, 0, 'L')
          pdf.cell(45, h, "Username", 0, 0, 'L')
          pdf.cell(30, h, "MAC", 0, 0, 'L')
          pdf.cell(40, h, "Service", 0, 0, 'L')
          pdf.cell(30, h, "Method", 0, 0, 'L')
          pdf.cell(40, h, "NAS", 0, 0, 'L')
          pdf.cell(30, h, "NAS IP", 0, 0, 'L')
          pdf.cell(20, h, "Media", 0, 0, 'L')
          pdf.cell(35, h, "Port/SSID", 0, 1, 'L')
          
          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               REVIEW['failed_authorization']=''
               if row[0] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    if row[2]=='':
                         red_list.append(row[1])
                    else:
                         red_list.append(row[2])
                    REVIEW['failed_authorization']='High'
               elif row[0] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['failed_authorization']!='High':
                         REVIEW['failed_authorization']='Med'
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               value=normalize_mac(row[1])
               if row[1]=='':
                   name=''
               elif value==row[2]:
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[1], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[1]
               pdf.cell(45, H, name, 0, 0, 'L', True)
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(row[2], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=row[2]
               pdf.cell(30, H, name, 0, 0, 'L', True)
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[9], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[9]
               pdf.cell(40, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, row[10], 0, 0, 'L', True)
               if ANON_NAS:
                    name,ANON_NAS_NO=get_anonymous_name(row[5], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                    name2=name
               else:
                    name=row[4]
                    name2=row[5]
               pdf.cell(40, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, name2, 0, 0, 'L', True)
               if row[3]=='5':
                    label='Other'
                    value=''
               elif row[3]=='15':
                    label='Wired'
                    value=row[8]
               elif row[3]=='19':
                    label='Wifi'
                    value=row[6]
               else:
                    label=row[3]
                    value=''
                    pdf.set_fill_color(255,0,0)
                    if row[2]=='':
                         red_list.append(row[1])
                    else:
                         red_list.append(row[2])
               pdf.cell(20, H, label, 0, 0, 'L', True)
               pdf.cell(35, H, value, 0, 1, 'L', True)
               row = cur.fetchone()

          if ANON_MAC is False:
            if whitelist_mac:
               pdf.ln('')
               pdf.cell(0, h, "MAC whitelist "+section['whitelist'], 0, 1, 'L')
          if ANON_USER is False:
            if whitelist_user:
               pdf.ln('')
               pdf.cell(0, h, "Username whitelist "+section['whitelist'], 0, 1, 'L')
               
          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          if len(red_list)==0:
               pdf.ln(h)
          if DEBUG:
              print('Leaving failed_authorization')
          return red_list


############################################# 
# Top TACACS Authentication
def tacacs_auths(conn, pdf):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     red_list =[]
     if DEBUG:
         print('Entering tacacs_auths')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top TACACS Authentications')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          threshold=int(section['threshold'])
          whitelist=section['whitelist']     
          whitelist=whitelist.replace(",","','")     # replace the coma with ',' so that SQL will work

          delta=datetime.strptime(END,'%Y-%m-%d')-datetime.strptime(START,'%Y-%m-%d')
          red_threshold=threshold*delta.days
          amber_threshold=red_threshold//10
          
          cmd="SELECT username, nad_ip, remote_addr, count(*) AS total, count(*) FILTER (WHERE tacacs.error_code=0), count(*) FILTER (WHERE tacacs.error_code!=0) FROM tacacs JOIN cppm_error_codes ON tacacs.error_code = cppm_error_codes.error_code WHERE timestamp >= '{}' AND timestamp < '{}' AND username NOT IN ('{}') GROUP BY username, nad_ip, remote_addr ORDER BY total DESC LIMIT 15".format(START,END,whitelist)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     username
               # row[1]     nad_ip
               # row[2]     local_address
               # row[3]     count
               # row[4]     success
               # row[5]     failed

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+" (based on "+str(threshold)+" auths per day), Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(30, h, "", 0, 0, 'L')
          pdf.cell(60, h, "Username", 0, 0, 'L')
          pdf.cell(60, h, "Source", 0, 0, 'L')
          pdf.cell(60, h, "Destination", 0, 0, 'L')
          pdf.cell(20, h, "Auths", 0, 0, 'L')
          pdf.cell(20, h, "Success", 0, 0, 'L')
          pdf.cell(20, h, "Failed", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               REVIEW['tacacs_auths']=''
               if row[3] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[0])
                    REVIEW['tacacs_auths']='High'
               elif row[3] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['tacacs_auths']!='High':
                         REVIEW['tacacs_auths']='Med'
               pdf.cell(30, H, "", 0, 0, 'L')
               if row[0]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[0], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
                    src='XXXXX'
                    dst='YYYYY'
               else:
                    name=row[0]
                    src=str(row[2])
                    dst=str(row[1])
               pdf.cell(60, H, name, 0, 0, 'L', True)
               pdf.cell(60, H, src, 0, 0, 'L', True)
               pdf.cell(60, H, dst, 0, 0, 'L', True)
               pdf.cell(20, H, str(row[3]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[4]), 0, 0, 'L', True)
               pdf.cell(20, H, str(row[5]), 0, 1, 'L', True)
               row = cur.fetchone()

          pdf.ln('')
          if ANON_USER is False:
            if whitelist:
               pdf.cell(0, h, "Username whitelist "+section['whitelist'], 0, 1, 'L')
               pdf.ln('')
          
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if len(red_list)==0:
               pdf.ln(h)
          if DEBUG:
              print('Leaving tacacs_auths')
          return red_list


############################################# 
# Top TACACS auth details
def tacacs_auth_details(conn, pdf, user):

     global ANON_NAS
     global ANON_NAS_NO
     global ANON_NAS_DIC

     if DEBUG:
         print('Entering tacacs_auth_details, user:',user)
     cur = conn.cursor()
     try:
          cmd="SELECT count(*) AS total, error_code_str, service, remote_addr AS local_ip, nads.name, nad_ip FROM tacacs JOIN cppm_error_codes ON tacacs.error_code = cppm_error_codes.error_code JOIN nads ON tacacs.nad_ip = nads.ip WHERE timestamp >= '{}' AND timestamp < '{}' AND tacacs.req_type = 'TACACS_AUTHENTICATION' AND username='{}' GROUP BY service, remote_addr, nads.name, nad_ip, error_code_str ORDER BY total DESC LIMIT 10".format(START,END, user)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     Auths
               # row[1]     Error
               # row[2]     Service
               # row[3]     Local device
               # row[4]     NAS
               # row[5]     NAS IP

          pdf.set_font("Arial", 'B', size = 16)
          value="TACACS \'"+user+"\' details"
          pdf.cell(0, h, value, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(15, h, "Auths", 0, 0, 'L')
          pdf.cell(45, h, "Error", 0, 0, 'L')
          pdf.cell(45, h, "Service", 0, 0, 'L')
          pdf.cell(30, h, "Local Device", 0, 0, 'L')
          pdf.cell(45, h, "NAS", 0, 0, 'L')
          pdf.cell(30, h, "NAS IP", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               pdf.cell(15, H, str(row[0]), 0, 0, 'L', True)
               pdf.cell(45, H, row[1], 0, 0, 'L', True)
               if ANON_SERVICE:
                    name,ANON_SERVICE_NO=get_anonymous_name(row[2], ANON_SERVICE_DIC, ANON_SERVICE_NO, 'Anonymous Service')
               else:
                    name=row[2]
               pdf.cell(45, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, row[3], 0, 0, 'L', True)
               if ANON_NAS:
                    name,ANON_NAS_NO=get_anonymous_name(row[5], ANON_NAS_DIC, ANON_NAS_NO, 'AnonNAS')
                    name2=name
               else:
                    name=row[4]
                    name=row[5]
               pdf.cell(45, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, name2, 0, 1, 'L', True)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving tacacs_auth_details')


############################################# 
# Create graph of TACACS Users auths over time
def tacacs_auth_graph(conn, pdf, user):

     global ANON_USER
     global ANON_USER_DIC
     global ANON_USER_NO
     global FILE_INDEX

     if DEBUG:
         print('Entering tacacs_auth_graph, user: ',user)
     cur=conn.cursor()
     times=[]
     successes=[]
     failures=[]
     try:
          pdf.set_font("Arial", 'B', size = 16)
          if row[0]=='':
              name=''
          elif ANON_USER:
               name,ANON_USER_NO=get_anonymous_name(row[0], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
          else:
               name=user
          value="TACACS User \'"+name+"\' Auths per hour"
          pdf.cell(0, h, value, 0, 1, 'L')
     # execute a statement

          f=plt.figure()
          plt.title(value)
          plt.ylabel('authentications')
          plt.xlabel('time')
          plt.xticks(rotation=90)
          plt.grid(True)

          cmd="SELECT Auth_hour, COUNT(error_code) FILTER (WHERE error_code = 0) AS Success, COUNT(error_code) FILTER (WHERE error_code !=0) AS Failed FROM (SELECT date_trunc('hour', tacacs.timestamp) AS Auth_hour, error_code FROM tacacs JOIN cppm_cluster ON tacacs.cppm_uuid=cppm_cluster.uuid WHERE username='{}' AND timestamp >= '{}' AND timestamp < '{}' AND req_type = 'TACACS_AUTHENTICATION' AND cppm_cluster.management_ip != '{}') tmp GROUP BY Auth_hour ORDER BY Auth_hour ASC".format(user, START, END, IGNORE)
#          print(cmd)
          cur.execute(cmd)

               # get start time
          t=datetime.strptime(START, '%Y-%m-%d')
          end=datetime.strptime(END, '%Y-%m-%d')
               # add timezone
               # as return from SQL includes timezone
          expect_time = t.replace(tzinfo=timezone('UTC'))
          end_time = end.replace(tzinfo=timezone('UTC'))
          row = cur.fetchone()
          while row is not None:
#               if DEBUG:
#                   print('Row=',row)
               timestamp = row[0]
               success = int(row[1])
               failed = int(row[2])
#               print('Timestamp', timestamp, 'Success', success, 'Failed', failed, 'Expect_time', expect_time)
                    # Fill in any missing gaps
               while timestamp > expect_time:
#                    print('missing @', expect_time, 'got', timestamp)
                    times.append(expect_time)
                    successes.append(0)
                    failures.append(0)
                    expect_time = expect_time + timedelta(hours=1)
               expect_time = expect_time + timedelta(hours=1)
               times.append(timestamp)
               successes.append(success)
               failures.append(failed)
               row = cur.fetchone()

          while expect_time<=end_time:
#               print('end missing @', expect_time, 'got', timestamp)
               times.append(expect_time)
               successes.append(0)
               failures.append(0)
               expect_time = expect_time + timedelta(hours=1)

#          print('Time, Successes, Failures')
#          j=0
#          for i in times:
#               print(i, successes[j], failures[j])
#               j+=1

          plt.plot(times, successes, 'g-')
          plt.plot(times, failures, 'r-')

#          plt.show()

               # WARNING I change the file name on each one as Linux 
               # seems to cache the first one and uses that!
               # OK a Linux flush might fix this but easier to 
               # just have unique graphs
          FILE_INDEX+=1
          filename='graph'+str(FILE_INDEX)
          plt.savefig(filename, format='png', bbox_inches='tight')
          plt.close()

          pdf.image(filename, w=LAND_W, h=GRAPH_H, type='PNG')
          if os.path.exists(filename):
               os.remove(filename)
               
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h)
          if DEBUG:
              print('Leaving tacacs_auth_graph')


############################################# 
# Top Device Session Duration
def device_session_duration(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     red_list =[]
     if DEBUG:
         print('Entering device_session_duration')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Device Session Duration')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          red_duration=int(section['duration'])
          amber_duration=red_duration//10
          whitelist_mac=section['whitelist_mac']     
          whitelist_mac=whitelist_mac.replace(",","','")     # replace the coma with ',' so that SQL will work
          whitelist_user=section['whitelist_user']     
          whitelist_user=whitelist_user.replace(",","','")     # replace the coma with ',' so that SQL will work
          
          cmd="SELECT COALESCE(calling_station_id,'') AS MAC, COALESCE(radius_acct.username,''), round(sum(duration)/86400,0) AS Days, round(sum(input_bytes)/1000000000,3) AS In_GB, round(sum(output_bytes)/1000000000,3) AS Out_GB, round((sum(input_bytes)+sum(output_bytes))/1000000000,3) AS Total_GB, COALESCE(endpoints.device_category,'Not Known') FROM radius_acct JOIN endpoints ON radius_acct.calling_station_id=endpoints.mac WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL AND (calling_station_id NOT IN ('{}') OR radius_acct.username NOT IN ('{}')) GROUP BY radius_acct.username, calling_station_id, endpoints.device_category ORDER BY Days DESC LIMIT 15".format(START,END,whitelist_mac,whitelist_user)
#          cmd="SELECT COALESCE(calling_station_id,'') AS MAC, COALESCE(username,''), round(sum(duration)/86400,0) AS Days, round(sum(input_bytes)/1000000000,3) AS In_GB, round(sum(output_bytes)/1000000000,3) AS Out_GB, round((sum(input_bytes)+sum(output_bytes))/1000000000,3) AS Total_GB FROM radius_acct WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL AND (calling_station_id NOT IN ('{}') OR username NOT IN ('{}')) GROUP BY username, calling_station_id ORDER BY Days DESC LIMIT 15".format(START,END,whitelist_mac,whitelist_user)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     mac
               # row[1]     username
               # row[2]     days
               # row[3]     in_Gbytes
               # row[4]     out_Gbytes
               # row[5]     total_Gbytes
               # row[6]     device type

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red duration="+str(red_duration)+" days, Amber duration="+str(amber_duration)+" days", 0, 1, 'L')
          pdf.cell(35, h, "MAC", 0, 0, 'L')
          pdf.cell(60, h, "Username", 0, 0, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "Days", 0, 0, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(30, h, "Out GBytes", 0, 0, 'L')
          pdf.cell(30, h, "In GBytes", 0, 0, 'L')
          pdf.cell(30, h, "Total GBytes", 0, 0, 'L')
          pdf.cell(30, h, "Device Type", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               REVIEW['session_duration']=''
               mac=normalize_mac(row[0])
               if row[2] >= red_duration:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(mac)
                    REVIEW['session_duration']='High'
               elif row[2] >= amber_duration:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['session_duration']!='High':
                         REVIEW['session_duration']='Med'
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=mac
               pdf.cell(35, H, name, 0, 0, 'L', True)
               value=normalize_mac(row[1])
               if row[1]=='':
                    name=''
               elif value==mac:
                    name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[1], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[1]
               pdf.cell(60, H, name, 0, 0, 'L', True)
               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(30, H, str(row[2]), 0, 0, 'L', True)
               pdf.set_font("Arial", size = 11)
               pdf.cell(30, H, str(row[3]), 0, 0, 'L', True)
               pdf.cell(30, H, str(row[4]), 0, 0, 'L', True)
               pdf.cell(30, H, str(row[5]), 0, 0, 'L', True)
               if row[6]=='Not Known':
                    pdf.set_font("Arial", 'I', size = 11)
                    pdf.cell(30, H, row[6], 0, 1, 'L', True)
                    pdf.set_font("Arial", size = 11)
               else: 
                    pdf.cell(30, H, row[6], 0, 1, 'L', True)
               row = cur.fetchone()

          if ANON_MAC is False:
            if whitelist_mac:
               pdf.ln('')
               pdf.cell(0, h, "Device whitelist "+section['whitelist_mac'], 0, 1, 'L')
          if ANON_USER is False:
            if whitelist_user:
               pdf.ln('')
               pdf.cell(0, h, "Username whitelist "+section['whitelist_user'], 0, 1, 'L')

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          
     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving device_session_duration')


############################################# 
# Top Device Session Total data
def device_session_data(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     red_list =[]
     if DEBUG:
         print('Entering device_session_data')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Device Session Total Data Average per Day')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          red_threshold=int(section['threshold'])
          amber_threshold=red_threshold//10
          whitelist_mac=section['whitelist_mac']     
          whitelist_mac=whitelist_mac.replace(",","','")     # replace the coma with ',' so that SQL will work
          whitelist_user=section['whitelist_user']     
          whitelist_user=whitelist_user.replace(",","','")     # replace the coma with ',' so that SQL will work
          
          cmd="SELECT mac, username, round(Days), CASE WHEN Days <= 1 THEN round(in_gb) ELSE round(in_gb/Days) END AS in_ave_per_day, CASE WHEN Days <= 1 THEN round(out_gb) ELSE round(out_gb/Days) END AS out_ave_per_day, CASE WHEN Days <= 1 THEN round(total_gb) ELSE round(total_gb/Days) END AS total_ave_per_day, tmp.category FROM ( SELECT COALESCE(calling_station_id,'') AS MAC, COALESCE(radius_acct.username,'') AS username, sum(duration)/86400 AS Days, sum(input_bytes)/1000000000 AS In_GB, sum(output_bytes)/1000000000 AS Out_GB, (sum(input_bytes)+sum(output_bytes))/1000000000 AS Total_GB, COALESCE(endpoints.device_category,'Not Known') AS category FROM radius_acct JOIN endpoints ON endpoints.mac=radius_acct.calling_station_id WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL AND (calling_station_id NOT IN ('{}') OR radius_acct.username NOT IN ('{}')) GROUP BY radius_acct.username, calling_station_id, endpoints.device_category ORDER BY Total_GB DESC) tmp ORDER BY total_ave_per_day DESC LIMIT 15".format(START,END,whitelist_mac,whitelist_user)
#          cmd="SELECT mac, username, round(Days), CASE WHEN Days <= 1 THEN round(in_gb) ELSE round(in_gb/Days) END AS in_ave_per_day, CASE WHEN Days <= 1 THEN round(out_gb) ELSE round(out_gb/Days) END AS out_ave_per_day, CASE WHEN Days <= 1 THEN round(total_gb) ELSE round(total_gb/Days) END AS total_ave_per_day FROM ( SELECT COALESCE(calling_station_id,'') AS MAC, COALESCE(username,'') AS username, sum(duration)/86400 AS Days, sum(input_bytes)/1000000000 AS In_GB, sum(output_bytes)/1000000000 AS Out_GB, (sum(input_bytes)+sum(output_bytes))/1000000000 AS Total_GB FROM radius_acct WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL AND (calling_station_id NOT IN ('{}') OR username NOT IN ('{}')) GROUP BY username, calling_station_id ORDER BY Total_GB DESC) tmp ORDER BY total_ave_per_day DESC LIMIT 15".format(START,END,whitelist_mac,whitelist_user)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     mac
               # row[1]     username
               # row[2]     days
               # row[3]     average_in_Gbytes_per_day
               # row[4]     average_out_Gbytes_per_day
               # row[5]     average_total_Gbytes_per_day
               # row[6]     device category

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+", Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(35, h, "MAC", 0, 0, 'L')
          pdf.cell(60, h, "Username", 0, 0, 'L')
          pdf.cell(30, h, "Days", 0, 0, 'L')
          pdf.cell(30, h, "Out GBytes", 0, 0, 'L')
          pdf.cell(30, h, "In GBytes", 0, 0, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "Total GBytes", 0, 0, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(30, h, "Device Category", 0, 1, 'L')

          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               mac=normalize_mac(row[0])
               pdf.set_fill_color(255,255,255)
               REVIEW['device_session_data']=''
               if row[5] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(mac)
                    REVIEW['device_session_data']='High'
               elif row[5] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['device_session_data']!='High':
                         REVIEW['device_session_data']='Med'
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=mac
               pdf.cell(35, H, name, 0, 0, 'L', True)
               value=normalize_mac(row[1])
               if row[1]=='':
                    name=''
               elif value==mac:
                    name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[1], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[1]
               pdf.cell(60, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, str(row[2]), 0, 0, 'L', True)
               pdf.cell(30, H, str(row[3]), 0, 0, 'L', True)
               pdf.cell(30, H, str(row[4]), 0, 0, 'L', True)
               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(30, H, str(row[5]), 0, 0, 'L', True)
               pdf.set_font("Arial", size = 11)
               if row[6]=='Not Known':
                    pdf.set_font("Arial", 'I', size = 11)
                    pdf.cell(30, H, row[6], 0, 1, 'L', True)
                    pdf.set_font("Arial", size = 11)
               else: 
                    pdf.cell(30, H, row[6], 0, 1, 'L', True)
               row = cur.fetchone()

          if ANON_MAC is False:
            if whitelist_mac:
               pdf.ln('')
               pdf.cell(0, h, "Device whitelist "+section['whitelist_mac'], 0, 1, 'L')
          if ANON_USER is False:
            if whitelist_user:
               pdf.ln('')
               pdf.cell(0, h, "Username whitelist "+section['whitelist_user'], 0, 1, 'L')

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving device_session_data')


############################################# 
# Top Device Session received data
def device_session_data_rx(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     red_list =[]
     if DEBUG:
         print('Entering device_session_data_rx')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Device Session Received Data Average per Day')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          red_threshold=int(section['threshold'])
          amber_threshold=red_threshold//10
          whitelist_mac=section['whitelist_mac']     
          whitelist_mac=whitelist_mac.replace(",","','")     # replace the coma with ',' so that SQL will work
          whitelist_user=section['whitelist_user']     
          whitelist_user=whitelist_user.replace(",","','")     # replace the coma with ',' so that SQL will work
          
          cmd="SELECT mac, username, round(Days), CASE WHEN Days <= 1 THEN round(in_gb) ELSE round(in_gb/Days) END AS in_ave_per_day, CASE WHEN Days <= 1 THEN round(out_gb) ELSE round(out_gb/Days) END AS out_ave_per_day, CASE WHEN Days <= 1 THEN round(total_gb) ELSE round(total_gb/Days) END AS total_ave_per_day, tmp.category FROM ( SELECT COALESCE(calling_station_id,'') AS MAC, COALESCE(radius_acct.username,'') AS username, sum(duration)/86400 AS Days, sum(input_bytes)/1000000000 AS In_GB, sum(output_bytes)/1000000000 AS Out_GB, (sum(input_bytes)+sum(output_bytes))/1000000000 AS Total_GB, COALESCE(endpoints.device_category,'Not Known') AS category FROM radius_acct JOIN endpoints ON endpoints.mac=radius_acct.calling_station_id WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL AND (calling_station_id NOT IN ('{}') OR radius_acct.username NOT IN ('{}')) GROUP BY radius_acct.username, calling_station_id, endpoints.device_category ORDER BY Total_GB DESC) tmp ORDER BY out_ave_per_day DESC LIMIT 15".format(START,END,whitelist_mac,whitelist_user)
#          cmd="SELECT mac, username, round(Days), CASE WHEN Days <= 1 THEN round(in_gb) ELSE round(in_gb/Days) END AS in_ave_per_day, CASE WHEN Days <= 1 THEN round(out_gb) ELSE round(out_gb/Days) END AS out_ave_per_day, CASE WHEN Days <= 1 THEN round(total_gb) ELSE round(total_gb/Days) END AS total_ave_per_day FROM ( SELECT COALESCE(calling_station_id,'') AS MAC, COALESCE(username,'') AS username, sum(duration)/86400 AS Days, sum(input_bytes)/1000000000 AS In_GB, sum(output_bytes)/1000000000 AS Out_GB, (sum(input_bytes)+sum(output_bytes))/1000000000 AS Total_GB FROM radius_acct WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL AND (calling_station_id NOT IN ('{}') OR username NOT IN ('{}')) GROUP BY username, calling_station_id ORDER BY Total_GB DESC) tmp ORDER BY out_ave_per_day DESC LIMIT 15".format(START,END,whitelist_mac,whitelist_user)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     mac
               # row[1]     username
               # row[2]     days
               # row[3]     in_Gbytes
               # row[4]     out_Gbytes
               # row[5]     total_Gbytes
               # row[6]     device category

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+", Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(35, h, "MAC", 0, 0, 'L')
          pdf.cell(60, h, "Username", 0, 0, 'L')
          pdf.cell(30, h, "Days", 0, 0, 'L')
          pdf.cell(30, h, "Out GBytes", 0, 0, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "In GBytes", 0, 0, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(30, h, "Total GBytes", 0, 0, 'L')
          pdf.cell(30, h, "Device Category", 0, 1, 'L')

          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               REVIEW['device_session_data_rx']=''
               mac=normalize_mac(row[0])
               if row[4] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(mac)
                    REVIEW['device_session_data_rx']='High'
               elif row[4] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['device_session_data_rx']!='High':
                         REVIEW['device_session_data_rx']='Med'
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(row[0], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=mac
               pdf.cell(35, H, name, 0, 0, 'L', True)
               value=normalize_mac(row[1])
               if row[1]=='':
                   name=''
               if value==mac:
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[1], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[1]
               pdf.cell(60, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, str(row[2]), 0, 0, 'L', True)
               pdf.cell(30, H, str(row[3]), 0, 0, 'L', True)
               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(30, H, str(row[4]), 0, 0, 'L', True)
               pdf.set_font("Arial", size = 11)
               pdf.cell(30, H, str(row[5]), 0, 0, 'L', True)
               if row[6]=='Not Known':
                    pdf.set_font("Arial", 'I', size = 11)
                    pdf.cell(30, H, row[6], 0, 1, 'L', True)
                    pdf.set_font("Arial", size = 11)
               else: 
                    pdf.cell(30, H, row[6], 0, 1, 'L', True)
               row = cur.fetchone()

          if ANON_MAC is False:
            if whitelist_mac:
               pdf.ln('')
               pdf.cell(0, h, "Device whitelist "+section['whitelist_mac'], 0, 1, 'L')
          if ANON_USER is False:
            if whitelist_user:
               pdf.ln('')
               pdf.cell(0, h, "Username whitelist "+section['whitelist_user'], 0, 1, 'L')

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
               print('Leaving device_session_data_rx')


############################################# 
# Top Device Session transmitted data
def device_session_data_tx(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     red_list =[]
     if DEBUG:
         print('Entering device_session_data_tx')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'Top Device Session Transmitted Data Average per Day')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     
          red_threshold=int(section['threshold'])
          amber_threshold=red_threshold//10
          whitelist_mac=section['whitelist_mac']     
          whitelist_mac=whitelist_mac.replace(",","','")     # replace the coma with ',' so that SQL will work
          whitelist_user=section['whitelist_user']     
          whitelist_user=whitelist_user.replace(",","','")     # replace the coma with ',' so that SQL will work
          
          cmd="SELECT mac, username, round(Days), CASE WHEN Days <= 1 THEN round(in_gb) ELSE round(in_gb/Days) END AS in_ave_per_day, CASE WHEN Days <= 1 THEN round(out_gb) ELSE round(out_gb/Days) END AS out_ave_per_day, CASE WHEN Days <= 1 THEN round(total_gb) ELSE round(total_gb/Days) END AS total_ave_per_day, tmp.category FROM ( SELECT COALESCE(calling_station_id,'') AS MAC, COALESCE(radius_acct.username,'') AS username, sum(duration)/86400 AS Days, sum(input_bytes)/1000000000 AS In_GB, sum(output_bytes)/1000000000 AS Out_GB, (sum(input_bytes)+sum(output_bytes))/1000000000 AS Total_GB, COALESCE(endpoints.device_category,'Not Known') AS category FROM radius_acct JOIN endpoints ON endpoints.mac=radius_acct.calling_station_id WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL AND (calling_station_id NOT IN ('{}') OR radius_acct.username NOT IN ('{}')) GROUP BY radius_acct.username, calling_station_id, endpoints.device_category ORDER BY Total_GB DESC) tmp ORDER BY in_ave_per_day DESC LIMIT 15".format(START,END,whitelist_mac,whitelist_user)
#          cmd="SELECT mac, username, round(Days), CASE WHEN Days <= 1 THEN round(in_gb) ELSE round(in_gb/Days) END AS in_ave_per_day, CASE WHEN Days <= 1 THEN round(out_gb) ELSE round(out_gb/Days) END AS out_ave_per_day, CASE WHEN Days <= 1 THEN round(total_gb) ELSE round(total_gb/Days) END AS total_ave_per_day FROM ( SELECT COALESCE(calling_station_id,'') AS MAC, COALESCE(username,'') AS username, sum(duration)/86400 AS Days, sum(input_bytes)/1000000000 AS In_GB, sum(output_bytes)/1000000000 AS Out_GB, (sum(input_bytes)+sum(output_bytes))/1000000000 AS Total_GB FROM radius_acct WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL AND (calling_station_id NOT IN ('{}') OR username NOT IN ('{}')) GROUP BY username, calling_station_id ORDER BY Total_GB DESC) tmp ORDER BY in_ave_per_day DESC LIMIT 15".format(START,END,whitelist_mac,whitelist_user)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     mac
               # row[1]     username
               # row[2]     days
               # row[3]     in_Gbytes
               # row[4]     out_Gbytes
               # row[5]     total_Gbytes
               # row[6]     device category

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(0, h, "NOTE: Red threshold="+str(red_threshold)+", Amber threshold="+str(amber_threshold), 0, 1, 'L')
          pdf.cell(35, h, "MAC", 0, 0, 'L')
          pdf.cell(60, h, "Username", 0, 0, 'L')
          pdf.cell(30, h, "Days", 0, 0, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "Out GBytes", 0, 0, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(30, h, "In GBytes", 0, 0, 'L')
          pdf.cell(30, h, "Total GBytes", 0, 0, 'L')
          pdf.cell(30, h, "Device Category", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               REVIEW['device_session_data_tx']=''
               mac=normalize_mac(row[0])
               if row[3] > red_threshold:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(mac)
                    REVIEW['device_session_data_tx']='High'
               elif row[3] > amber_threshold:
                    pdf.set_fill_color(255,194,0)
                    if REVIEW['device_session_data_tx']!='High':
                         REVIEW['device_session_data_tx']='Med'
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(mac, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=mac
               pdf.cell(35, H, name, 0, 0, 'L', True)
               value=normalize_mac(row[1])
               if row[1]=='':
                    name=''
               elif value==mac:
                    name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[1], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[1]
               pdf.cell(60, H, name, 0, 0, 'L', True)
               pdf.cell(30, H, str(row[2]), 0, 0, 'L', True)
               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(30, H, str(row[3]), 0, 0, 'L', True)
               pdf.set_font("Arial", size = 11)
               pdf.cell(30, H, str(row[4]), 0, 0, 'L', True)
               pdf.cell(30, H, str(row[5]), 0, 0, 'L', True)
               if row[6]=='Not Known':
                    pdf.set_font("Arial", 'I', size = 11)
                    pdf.cell(30, H, row[6], 0, 1, 'L', True)
                    pdf.set_font("Arial", size = 11)
               else: 
                    pdf.cell(30, H, row[6], 0, 1, 'L', True)
               row = cur.fetchone()

          if ANON_MAC is False:
            if whitelist_mac:
               pdf.ln('')
               pdf.cell(0, h, "Device whitelist "+section['whitelist_mac'], 0, 1, 'L')
          if ANON_USER is False:
            if whitelist_user:
               pdf.ln('')
               pdf.cell(0, h, "Username whitelist "+section['whitelist_user'], 0, 1, 'L')
          
          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
               print('Leaving device_session_data_tx')


############################################# 
# Top User Sessions Duration
def user_sessions_duration(conn, pdf):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     red_list =[]
     if DEBUG:
         print('Entering user_sessions_duration')
     cur = conn.cursor()
     try:
          cmd="SELECT COALESCE(username,''), round(sum(duration)/86400,0) AS Days, round(sum(input_bytes)/1000000000,3) AS In_GB, round(sum(output_bytes)/1000000000,3) AS Out_GB, round((sum(input_bytes)+sum(output_bytes))/1000000000,3) AS Total_GB FROM radius_acct WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL GROUP BY username ORDER BY Days DESC LIMIT 15".format(START,END)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     username
               # row[1]     days
               # row[2]     in_Gbytes
               # row[3]     out_Gbytes
               # row[4]     total_Gbytes

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, "Top User Sessions Duration", 0, 1, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(0, h, "This is the consolidation of all the session duration for specific users ordered by longest duration down, thos could include multiple devices", 0, 1, 'L')
          pdf.cell(0, h, "NOTE: Red threshold=1 year & Amber threshold=3 months", 0, 1, 'L')
          pdf.cell(60, h, "Username", 0, 0, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "Days", 0, 0, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(30, h, "Out GBytes", 0, 0, 'L')
          pdf.cell(30, h, "In GBytes", 0, 0, 'L')
          pdf.cell(30, h, "Total GBytes", 0, 1, 'L')

          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               if row[1] > 365:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[0])
               elif row[1] > 90:
                    pdf.set_fill_color(255,194,0)
               if row[0]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[0], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[0]
               pdf.cell(60, h, name, 0, 0, 'L', True)
               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(30, h, str(row[1]), 0, 0, 'L', True)
               pdf.set_font("Arial", size = 11)
               pdf.cell(30, h, str(row[2]), 0, 0, 'L', True)
               pdf.cell(30, h, str(row[3]), 0, 0, 'L', True)
               pdf.cell(30, h, str(row[4]), 0, 1, 'L', True)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
               print('Leaving user_sessions_duration')


############################################# 
# Top User Sessions Total Data 
def user_sessions_data(conn, pdf):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     red_list =[]
     if DEBUG:
         print('Entering user_sessions_data')
     cur = conn.cursor()
     try:
          cmd="SELECT COALESCE(username,''), round(sum(duration)/86400,0) AS Days, round(sum(input_bytes)/1000000000,3) AS In_GB, round(sum(output_bytes)/1000000000,3) AS Out_GB, round((sum(input_bytes)+sum(output_bytes))/1000000000,3) AS Total_GB FROM radius_acct WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL GROUP BY username ORDER BY Total_GB DESC LIMIT 15".format(START,END)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     username
               # row[1]     days
               # row[2]     in_Gbytes
               # row[3]     out_Gbytes
               # row[4]     total_Gbytes

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, "Top User Sessions Total Data", 0, 1, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(0, h, "NOTE: Red threshold=1TB & Amber threshold=100GB", 0, 1, 'L')
          pdf.cell(60, h, "Username", 0, 0, 'L')
          pdf.cell(30, h, "Days", 0, 0, 'L')
          pdf.cell(30, h, "Out GBytes", 0, 0, 'L')
          pdf.cell(30, h, "In GBytes", 0, 0, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "Total GBytes", 0, 1, 'L')
          pdf.set_font("Arial", size = 11)

          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               if row[4] > 1000:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[0])
               elif row[4] > 100:
                    pdf.set_fill_color(255,194,0)
               if row[0]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[0], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[0]
               pdf.cell(60, h, name, 0, 0, 'L', True)
               pdf.cell(30, h, str(row[1]), 0, 0, 'L', True)
               pdf.cell(30, h, str(row[2]), 0, 0, 'L', True)
               pdf.cell(30, h, str(row[3]), 0, 0, 'L', True)
               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(30, h, str(row[4]), 0, 1, 'L', True)
               pdf.set_font("Arial", size = 11)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h*2)
          if DEBUG:
               print('Leaving user_sessions_data')


############################################# 
# Top User Sessions Tx Data 
def user_sessions_data_tx(conn, pdf):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     red_list =[]
     if DEBUG:
         print('Entering user_sessions_data_tx')
     cur = conn.cursor()
     try:
          cmd="SELECT COALESCE(username,''), round(sum(duration)/86400,0) AS Days, round(sum(input_bytes)/1000000000,3) AS In_GB, round(sum(output_bytes)/1000000000,3) AS Out_GB, round((sum(input_bytes)+sum(output_bytes))/1000000000,3) AS Total_GB FROM radius_acct WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL GROUP BY username ORDER BY Out_GB DESC LIMIT 15".format(START,END)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     username
               # row[1]     days
               # row[2]     in_Gbytes
               # row[3]     out_Gbytes
               # row[4]     total_Gbytes

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, "Top User Sessions Transmitted Data", 0, 1, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(0, h, "NOTE: Red threshold=1TB & Amber threshold=100GB", 0, 1, 'L')
          pdf.cell(60, h, "Username", 0, 0, 'L')
          pdf.cell(30, h, "Days", 0, 0, 'L')
          pdf.cell(30, h, "Out GBytes", 0, 0, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "In GBytes", 0, 0, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(30, h, "Total GBytes", 0, 1, 'L')

          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               if row[3] > 1000:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[0])
               elif row[3] > 100:
                    pdf.set_fill_color(255,194,0)
               if row[0]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[0], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[0]
               pdf.cell(60, h, name, 0, 0, 'L', True)
               pdf.cell(30, h, str(row[1]), 0, 0, 'L', True)
               pdf.cell(30, h, str(row[2]), 0, 0, 'L', True)
               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(30, h, str(row[3]), 0, 0, 'L', True)
               pdf.set_font("Arial", size = 11)
               pdf.cell(30, h, str(row[4]), 0, 1, 'L', True)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h*2)
          if DEBUG:
               print('Leaving user_sessions_data_tx')


############################################# 
# Top User Sessions Rx Data 
def user_sessions_data_rx(conn, pdf):

     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     red_list =[]
     if DEBUG:
         print('Entering user_sessions_data_rx')
     cur = conn.cursor()
     try:
          cmd="SELECT COALESCE(username,''), round(sum(duration)/86400,0) AS Days, round(sum(input_bytes)/1000000000,3) AS In_GB, round(sum(output_bytes)/1000000000,3) AS Out_GB, round((sum(input_bytes)+sum(output_bytes))/1000000000,3) AS Total_GB FROM radius_acct WHERE (end_time >= '{}' OR end_time IS NULL) AND start_time < '{}' AND duration IS NOT NULL GROUP BY username ORDER BY In_GB DESC LIMIT 15".format(START,END)
#          print(cmd)
          cur.execute(cmd)

               # row[0]     username
               # row[1]     days
               # row[2]     in_Gbytes
               # row[3]     out_Gbytes
               # row[4]     total_Gbytes

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, "Top User Sessions Received Data", 0, 1, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(0, h, "NOTE: Red threshold=1TB & Amber threshold=100GB", 0, 1, 'L')
          pdf.cell(60, h, "Username", 0, 0, 'L')
          pdf.cell(30, h, "Days", 0, 0, 'L')
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(30, h, "Out GBytes", 0, 0, 'L')
          pdf.set_font("Arial", size = 11)
          pdf.cell(30, h, "In GBytes", 0, 0, 'L')
          pdf.cell(30, h, "Total GBytes", 0, 1, 'L')

          row = cur.fetchone()
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.set_fill_color(255,255,255)
               if row[2] > 1000:
                    pdf.set_fill_color(255,0,0)
                    red_list.append(row[0])
               elif row[2] > 100:
                    pdf.set_fill_color(255,194,0)
               if row[0]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[0], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=row[0]
               pdf.cell(60, h, name, 0, 0, 'L', True)
               pdf.cell(30, h, str(row[1]), 0, 0, 'L', True)
               pdf.set_font("Arial", 'B', size = 11)
               pdf.cell(30, h, str(row[2]), 0, 0, 'L', True)
               pdf.set_font("Arial", size = 11)
               pdf.cell(30, h, str(row[3]), 0, 0, 'L', True)
               pdf.cell(30, h, str(row[4]), 0, 1, 'L', True)
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(h*2)
          if DEBUG:
              print('Leaving user_sessions_data_rx')


############################################# 
# ClearPass audit
def audit(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC

     if DEBUG:
         print('Entering audit')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'ClearPass Audit')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd = "SELECT count(*) FROM cppm_config_audit WHERE updated_at >= '{}' AND updated_at < '{}'".format(START,END)
          cur.execute(cmd)

          row = cur.fetchone()
               # row[0] number of updates
          pdf.set_font("Arial", size = 11)
          pdf.multi_cell(0, H, comment, 0, 'L', False)
          pdf.ln('')

          cmd = "SELECT updated_at, updated_by, category, action, name FROM cppm_config_audit WHERE updated_at >= '{}' AND updated_at < '{}' ORDER BY id DESC LIMIT 15".format(START,END)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()
               # row[0] updated_at
               # row[1] username
               # row[2] category
               # row[3] action
               # row[4] name
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(60, h, "Time", 0, 0, 'L')
          pdf.cell(30, h, "User", 0, 0, 'L', )
          pdf.cell(75, h, "Category", 0, 0, 'L')
          pdf.cell(40, h, "Action", 0, 0, 'L')
          pdf.cell(60, h, "Change", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.cell(60, H, str(row[0]), 0, 0, 'L')
               if row[1]=='':
                   name=''
               elif ANON_USER:
                    name,ANON_USER_NO=get_anonymous_name(row[1], ANON_USER_DIC, ANON_USER_NO, 'AnonUser')
               else:
                    name=str(row[1])
               pdf.cell(30, H, name, 0, 0, 'L')
               pdf.cell(75, H, row[2], 0, 0, 'L')
               pdf.cell(40, H, row[3], 0, 0, 'L')
               value=normalize_mac(row[4])
               if value!='':        # Found a MAC address
                    if ANON_MAC:
                        name,ANON_MAC_NO=get_anonymous_name(value, ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
                    else:
                        name=value
                    pdf.cell(60, H, name, 0, 1, 'L')
               else:
                    pdf.cell(60, H, row[4], 0, 1, 'L')
               row = cur.fetchone()

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving audit')


############################################# 
# OnGuard summary
def onguard_summary(conn, pdf):

     if DEBUG:
         print('Entering onguard_summary')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', 'OnGuard Summary')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd = "SELECT count(*) AS total, count(*) FILTER (WHERE spt = 'UNKNOWN') AS Unknown, count(*) FILTER (WHERE spt = 'INFECTED') AS Infected, count(*) FILTER (WHERE spt = 'HEALTHY') AS Healthy, count(*) FILTER (WHERE spt = 'CHECKUP') AS Checkup, count(*) FILTER (WHERE spt = 'QUARANTINE') AS Quarantine, count(*) FILTER (WHERE spt = 'TRANSITION') AS Transition, count(*) FILTER (WHERE spt IS Null) AS NoStatus FROM endpoints WHERE device_category='Computer' AND updated_at >= '{}' AND updated_at < '{}'".format(START,END)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()
               # row[0] Total
               # row[1] Unknown
               # row[2] Infected
               # row[3] Healthy
               # row[4] Checkup
               # row[5] Quarantine
               # row[6] Transition
               # row[7] No Status
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(25, h, "Total", 0, 0, 'L')
          pdf.cell(25, h, "Unknown", 0, 0, 'L')
          pdf.cell(25, h, "Infected", 0, 0, 'L', )
          pdf.cell(25, h, "Healthy", 0, 0, 'L', )
          pdf.cell(25, h, "Checkup", 0, 0, 'L')
          pdf.cell(25, h, "Quarantine", 0, 0, 'L')
          pdf.cell(25, h, "Transition", 0, 0, 'L')
          pdf.cell(25, h, "No Status", 0, 1, 'L')

          pdf.set_font("Arial", size = 11)
          if row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.cell(25, H, str(row[0]), 0, 0, 'L')
               pdf.cell(25, H, str(row[1]), 0, 0, 'L')
               pdf.cell(25, H, str(row[2]), 0, 0, 'L')
               pdf.cell(25, H, str(row[3]), 0, 0, 'L')
               pdf.cell(25, H, str(row[4]), 0, 0, 'L')
               pdf.cell(25, H, str(row[5]), 0, 0, 'L')
               pdf.cell(25, H, str(row[6]), 0, 0, 'L')
               pdf.cell(25, H, str(row[6]), 0, 1, 'L')
               row = cur.fetchone()

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving onguard_summary')


############################################# 
# OnGuard failed
def onguard_failed(conn, pdf):

     global ANON_MAC
     global ANON_MAC_NO
     global ANON_MAC_DIC
     global ANON_IP
     global ANON_IP_NO
     global ANON_IP_DIC
     global ANON_USER
     global ANON_USER_NO
     global ANON_USER_DIC
     global ANON_HOST
     global ANON_HOST_NO
     global ANON_HOST_DIC

     if DEBUG:
         print('Entering onguard_failed')
     cur = conn.cursor()
     try:
          section = configdb('report.ini', '10 Most Recent OnGuard Posture Failures')
          heading=section['title']     
          print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
          comment=section['comment']     

          pdf.set_font("Arial", 'B', size = 16)
          pdf.cell(0, h, heading, 0, 1, 'L')

          cmd = "SELECT updated_at, mac, ip, hostname, posture->'posture_result'->'spt' AS unhealthy, posture FROM endpoints WHERE posture->'posture_result'->>'spt' != 'HEALTHY' AND device_category='Computer' AND updated_at >= '{}' AND updated_at < '{}' ORDER BY updated_at DESC LIMIT 10".format(START,END)
#          print(cmd)
          cur.execute(cmd)

          row = cur.fetchone()
               # row[0] updated_at
               # row[1] MAC
               # row[2] IP
               # row[3] Hostname
               # row[4] Posture Status
               # row[5] Posture
          pdf.set_font("Arial", 'B', size = 11)
          pdf.cell(40, h, "Date", 0, 0, 'L')
          pdf.cell(30, h, "MAC", 0, 0, 'L')
          pdf.cell(25, h, "IP", 0, 0, 'L', )
          pdf.cell(35, h, "Hostname", 0, 0, 'L', )
          pdf.cell(35, h, "Username", 0, 0, 'L', )
          pdf.cell(70, h, "OS", 0, 1, 'L', )

          pdf.set_font("Arial", size = 11)
          while row is not None:
               if DEBUG:
                   print('Row=',row)
               pdf.cell(40, H, row[0].strftime('%Y-%m-%d %H:%M'), 0, 0, 'L')
               if ANON_MAC:
                    name,ANON_MAC_NO=get_anonymous_name(row[1], ANON_MAC_DIC, ANON_MAC_NO, 'AnonMAC')
               else:
                    name=row[1]
               pdf.cell(30, H, name, 0, 0, 'L')
               if ANON_IP:
                    name,ANON_IP_NO=get_anonymous_name(row[2], ANON_IP_DIC, ANON_IP_NO, 'AnonIP')
               else:
                    name=row[2]
               pdf.cell(25, H, name, 0, 0, 'L')
               if ANON_HOST:
                    name,ANON_HOST_NO=get_anonymous_name(row[3], ANON_HOST_DIC, ANON_HOST_NO, 'AnonHost')
               else:
                    name=row[3]
               pdf.cell(35, H, name, 0, 0, 'L')
               pdf.cell(35, H, row[5]['system_info']['active_user_name'], 0, 0, 'L')
               pdf.cell(70, H, row[5]['system_info']['os_name_version'], 0, 1, 'L')
               for i in row[5]['posture_result']['unhealthy']:
                    pdf.cell(5, H, '', 0, 0, 'L')
                    pdf.cell(20, H, 'Unhealthy', 0, 0, 'L')
#                    print(i, end='')
                    result_dict = row[5]['posture_result'][i.lower()]
                    components = list(result_dict.keys())
                    for j in components:
                         if j != 'apt':     
                              value=i+'('+j+'):'
#                              print(value,'Unhealthy ', end='')
                              pdf.cell(90, H, value, 0, 0, 'L')
                              k=result_dict[j]['failed_checks']
                              if 'LastScanTimeCheck' in k:
                                   values=str(row[5]['posture_input'][i.lower()][j])
                                   pdf.multi_cell(150, H, values, 0, 'L', True)
                                   pdf.ln('')
                              elif 'ApplicationNotInstalled' in k:
#                                   print('Application Not Installed')
                                   pdf.cell(70, H, 'Application Not Installed', 0, 1, 'L')
                              elif 'StatusCheck' in k:
                                   values=str(row[5]['posture_input'][i.lower()][j])
#                                   print(values)
                                   pdf.multi_cell(150, H, values, 0, 'L', True)
                                   pdf.ln(1)
                              else:
                                   print('What is this=', result_dict[j])
                                   pdf.cell(40, H, 'What is this?', 0, 0, 'L')
                                   pdf.multi_cell(150, h, str(result_dict[j]), 0, 'L', True)
                                   pdf.ln(1)
                              
               pdf.ln(1)
               row = cur.fetchone()

          pdf.ln('')
          pdf.multi_cell(0, H, comment, 0, 'L', False)

     except (Exception, psycopg2.DatabaseError) as error:
          print(error)
     finally:
          pdf.ln(2*h)
          if DEBUG:
              print('Leaving onguard_failed')


############################################# 
# Recommendations
def recommendations(conn, pdf):

#    suggest{}

    if DEBUG:
        print('Entering recommendations', REVIEW)
    cur = conn.cursor()
    try:
        section = configdb('report.ini', 'Recommendations')
        heading=section['title']     
        print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
        comment=section['comment']     
        
        pdf.set_font("Arial", 'B', size = 16)
        pdf.cell(0, h, heading, 0, 1, 'L')

            # print out the high issues
        pdf.set_font("Arial", 'B', size = 14)
        pdf.cell(100, H, 'Priority Ordered Review List', 0, 1, 'L')
#        print('These areas must be reviewed')
        pdf.set_font("Arial", size = 11)
        pdf.set_fill_color(255,0,0)
        index=1
        while True:
            if section[str(index)] in REVIEW:
                i=section[str(index)]
                if REVIEW[i]=='High':
                    pdf.cell(10, H, '', 0, 0, 'L', True)
                    pdf.cell(90, H, i, 0, 1, 'L', True)
#                    print(i)
            index+=1
            if index>23:
                break

            # print out the medium issues
#        pdf.set_font("Arial", 'B', size = 14)
#        pdf.cell(100, H, 'These areas need reviewing', 0, 1, 'L')
#        print('These areas need reviewing')
#        pdf.set_font("Arial", size = 11)
        pdf.set_fill_color(255,194,0)
        index=1
        while section[str(index)] in REVIEW:
            i=section[str(index)]
            if REVIEW[i]=='Med':
                pdf.cell(10, H, '', 0, 0, 'L', True)
                pdf.cell(90, H, i, 0, 1, 'L', True)
#                print(i)
            index+=1

        pdf.ln('')
        pdf.multi_cell(0, H, comment, 0, 'L', False)

    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        pdf.ln(2*h)
        if DEBUG:
           print('Leaving recommandations')

def contents():

    pdf.set_font("Arial", 'B', size = 12)
    pdf.cell(0, H, 'Contents',0,1,'C')
    pdf.set_font("Arial", size = 11)
    section = configdb('report.ini', 'ClearPass Cluster Authentication Load Distribution')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Top ClearPass Cluster Events')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Access License Usage over Time')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
#    section = configdb('report.ini', 'Top ClearPass Cluster Alerts')
#    heading=section['title']     
#    pdf.cell(20, H, '',0,0,'L')
#    pdf.cell(130, H, heading,0,1,'L')
#    section = configdb('report.ini', 'ClearPass Error Alerts per hour')
#    heading=section['title']     
#    pdf.cell(20, H, '',0,0,'L')
#    pdf.cell(130, H, heading,0,0,'L')
#    section = configdb('report.ini', 'ClearPass Error Alerts Burst Details')
#    heading=section['title']     
#    pdf.cell(20, H, '',0,0,'L')
#    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Endpoint Categorization')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Endpoint IP Address Assignment')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Endpoint MAC & IP Address Details')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Endpoints with Randomized MAC Addresses')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Number of Suspected Spoofs Detected')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Missing Known Endpoints')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Authentications per Service')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Top Failed Authentications per Service')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Top Endpoints not Matching a Service')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Top Wired Endpoints Auths')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Top Wireless Endpoints Auths')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Top Virtual User Auths')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Top 802.1X Users')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Top NAS with Most Authentications')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Top NAS with Least Authentications')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Top Failed Authorization')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Top 802.1X Users with Multiple Devices')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Top 802.1X Devices with Multiple Users')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Top Wired Devices that have Moved')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Top Wireless Devices with Multiple SSID')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Top TACACS Authentications')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Top Device Session Duration')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Top Device Session Total Data Average per Day')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', 'Top Device Session Transmitted Data Average per Day')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'Top Device Session Received Data Average per Day')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
#    section = configdb('report.ini', 'Number of Guests Created over Time')
#    heading=section['title']     
#    pdf.cell(20, H, '',0,0,'L')
#    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'ClearPass Audit')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,0,'L')
    section = configdb('report.ini', 'OnGuard Summary')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')
    section = configdb('report.ini', '10 Most Recent OnGuard Posture Failures')
    heading=section['title']     
    pdf.cell(20, H, '',0,0,'L')
    pdf.cell(130, H, heading,0,1,'L')


def anonymous_setup():
    global ANON_MAC
    global ANON_MAC_NO
    global ANON_IP
    global ANON_IP_NO
    global ANON_USER
    global ANON_USER_NO
    global ANON_HOST
    global ANON_HOST_NO
    global ANON_NAS
    global ANON_NAS_NO
    global ANON_CPPM
    global ANON_CPPM_NO
    global ANON_SERVICE
    global ANON_SERVICE_NO

    if DEBUG:
        print('Entering anonymous_setup')

    ANON_MAC=False
    ANON_MAC_NO=0
    ANON_IP=False
    ANON_IP=0
    ANON_USER=False
    ANON_USER_NO=0
    ANON_HOST=False
    ANON_HOST_NO=0
    ANON_NAS=False
    ANON_NAS_NO=0
    ANON_CPPM=False
    ANON_CPPM_NO=0
    ANON_SERVICE=False
    ANON_SERVICE_NO=0
    if 'anon_mac' in params:
        if params['anon_mac']=='True':
            ANON_MAC=True
    if 'anon_ip' in params:
        if params['anon_ip']=='True':
            ANON_IP=True
    if 'anon_user' in params:
        if params['anon_user']=='True':
            ANON_USER=True
    if 'anon_host' in params:
        if params['anon_host']=='True':
            ANON_HOST=True
    if 'anon_nas' in params:
        if params['anon_nas']=='True':
            ANON_NAS=True
    if 'anon_cppm' in params:
        if params['anon_cppm']=='True':
            ANON_CPPM=True
    if 'anon_service' in params:
        if params['anon_service']=='True':
            ANON_SERVICE=True

    if DEBUG:
        print('Leaving anonymous_setup')


def anonymous_output():
    global ANON_MAC
    global ANON_MAC_NO
    global ANON_MAC_DIC
    global ANON_IP
    global ANON_IP_NO
    global ANON_IP_DIC
    global ANON_USER
    global ANON_USER_NO
    global ANON_USER_DIC
    global ANON_HOST
    global ANON_HOST_NO
    global ANON_HOST_DIC
    global ANON_NAS
    global ANON_NAS_NO
    global ANON_NAS_DIC
    global ANON_CPPM
    global ANON_CPPM_NO
    global ANON_CPPM_DIC
    global ANON_SERVICE
    global ANON_SERVICE_NO
    global ANON_SERVICE_DIC

    if DEBUG:
        print('Entering anonymous_output')

        # Print out the anonymous tables into a anonymous.csv file
    anon_fh=open('anonymous.csv', 'w')
    print('\tAnonymous table')
    anon_fh.write('Anonymous Table\n')
    keys=[]
    if ANON_MAC:
        anon_fh.write('\nAnonymous MAC addresses mapping\n')
#        print('\nAnonymous MAC,MAC: ', ANON_MAC_DIC)
        for key in ANON_MAC_DIC.keys(): 
            string=ANON_MAC_DIC[key]+','+key+'\n'
            anon_fh.write(string)
    if ANON_USER:
        anon_fh.write('\nAnonymous Usernames mapping\n')
#        print('\nAnonymous User,User: ', ANON_USER_DIC)
        for key in ANON_USER_DIC.keys(): 
            string=ANON_USER_DIC[key]+','+key+'\n'
            anon_fh.write(string)
    if ANON_IP:
        anon_fh.write('\nAnonymous IP addresses mapping\n')
#        print('\nAnonymous IP,IP: ', ANON_IP_DIC)
        for key in ANON_IP_DIC.keys():
            string=ANON_IP_DIC[key]+','+key+'\n'
            anon_fh.write(string)
    if ANON_HOST:
#        print('\nAnonymous Host,Host: ', ANON_HOST_DIC)
        anon_fh.write('\nAnonymous Hostnames mapping\n')
        for key in ANON_HOST_DIC.keys():
            string=ANON_HOST_DIC[key]+','+key+'\n'
            anon_fh.write(string)
    if ANON_NAS:
        anon_fh.write('\nAnonymous NAS mapping\n')
#        print('\nAnonymous NAS,NAS: ', ANON_NAS_DIC)
        for key in ANON_NAS_DIC.keys():
            string=ANON_NAS_DIC[key]+','+key+'\n'
            anon_fh.write(string)
    if ANON_SERVICE:
        anon_fh.write('\nAnonymous Service mappings\n')
#        print('\nAnonymous Service,Service: ', ANON_SERVICE_DIC)
        for key in ANON_SERVICE_DIC.keys():
            string=ANON_SERVICE_DIC[key]+','+key+'\n'
            anon_fh.write(string)
    if ANON_CPPM:
        anon_fh.write('\nAnonymous ClearPass mappings\n')
#        print('\nAnonymous ClearPass,ClearPass: ', ANON_CPPM_DIC)
        for key in ANON_CPPM_DIC.keys():
            string=ANON_CPPM_DIC[key]+','+key+'\n'
            anon_fh.write(string)
    anon_fh.close()

    if DEBUG:
        print('Leaving anonymous_output')


def normalize_mac(mac):

#    print('normalize mac: ',mac)
    if len(mac)==17:
        if mac.find(':')==2:    # mac_colon ie fe:dc:ba:98:76:54, check for first ':'
            mac=mac.replace(':','')
        elif mac.find('-')==2:  # mac_hyphen ie aa:bb:cc:dd:ee:ff, check for first '-'
            mac=mac.replace('-','')
        else:                   # something else!
            return ''
    elif len(mac)==14 and mac.find('.')==4:  # mac_cisco ie 0123.4567.89AB. check for first '.'
        mac=mac.replace('.','')     # strip out '.'
    mac=mac.lower()
    if len(mac)==12:    # a basic mac ie 001122334455
        # really need to validate using re (regex) module to verify it only contains 0-9a-f characters
        return mac
    else:
#        print('normalize mac: What is this: ', mac)
        return ''


############################################# 
# Event Burst Details
def events_burst_details(conn, pdf, red_dates):

    global ANON_CPPM
    global ANON_CPPM_NO
    global ANON_CPPM_DIC

    if DEBUG:
        print('Entering events_burst_details, red_dates: ', red_dates)
    cur = conn.cursor()
    try:
        section = configdb('report.ini', 'ClearPass Error Events Burst Details')
        heading=section['title']     
        print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
        comment=section['comment']     
        
        pdf.set_font("Arial", 'B', size = 14)
        pdf.cell(0, h, heading, 0, 1, 'L')

            # print out the high issues
        pdf.set_font("Arial", size = 11)
        pdf.cell(100, H, comment, 0, 1, 'L')
#        print('These areas must be reviewed')

        for i in red_dates:
            start_burst=i.strftime('%Y-%m-%d %H:%M')
            if start_burst=='2020-01-01 00:00':
                break
            j=i+timedelta(hours=1)
            end_burst=j.strftime('%Y-%m-%d %H:%M')
            pdf.set_font("Arial", 'B', size = 11)
            pdf.cell(100, H, 'Event burst between '+start_burst+'-'+end_burst, 0, 1, 'L')

            cmd = "SELECT count(*), cppm_cluster.hostname, category, description FROM public.cppm_system_events JOIN cppm_cluster ON cppm_cluster.uuid=cppm_system_events.cppm_uuid WHERE level='ERROR' AND timestamp>='{}' AND timestamp<'{}' GROUP BY description, category, cppm_cluster.hostname ORDER BY count DESC".format(start_burst,end_burst)
#            print(cmd)
            cur.execute(cmd)

            row = cur.fetchone()
               # row[0] count
               # row[1] ClearPass
               # row[2] category
               # row[3] description
            pdf.cell(30, h, "Count", 0, 0, 'L')
            pdf.cell(40, h, "ClearPass", 0, 0, 'L')
            pdf.cell(40, h, "Category", 0, 0, 'L', )
            pdf.cell(100, h, "Description", 0, 1, 'L', )

            pdf.set_font("Arial", size = 11)
            while row is not None:
                if DEBUG:
                    print('Row=',row)
                pdf.cell(30, H, str(row[0]), 0, 0, 'L')
                if ANON_CPPM:
                    name,ANON_CPPM_NO=get_anonymous_name(row[1], ANON_CPPM_DIC, ANON_CPPM_NO, 'AnonCPPM')
                else:
                    name=row[1]
                pdf.cell(40, H, name, 0, 0, 'L')
                pdf.cell(40, H, row[2], 0, 0, 'L')
                pdf.cell(100, H, row[3], 0, 1, 'L')
                row = cur.fetchone()

    except (Exception) as error:
        print(error)
    finally:
        pdf.ln(2*h)
        if DEBUG:
            print('Leaving events_burst_details')


############################################# 
# Alerts Burst Details
def alerts_burst_details(conn, pdf, red_dates):

    global ANON_CPPM
    global ANON_CPPM_NO
    global ANON_CPPM_DIC

    if DEBUG:
        print('Entering alerts_burst_details, red_dates: ', red_dates)
    cur = conn.cursor()
    try:
        section = configdb('report.ini', 'ClearPass Error Alerts Burts Details')
        heading=section['title']     
        print('\t'+heading+' (timestamp='+str(datetime.now().time())+')')
        comment1=section['comment1']     
        comment2=section['comment2']     
        threshold=int(section['threshold'])
        whitelist=section['whitelist']
        replace1=section['replace1']
        replace2=section['replace2']
        replace3=section['replace3']
        
        pdf.set_font("Arial", 'B', size = 14)
        pdf.cell(0, h, heading, 0, 1, 'L')

        pdf.set_font("Arial", 'B', size = 12)
        pdf.multi_cell(0, H, comment1, 0, 'L', False)
        pdf.ln('')
        pdf.cell(0, h, "NOTE: Threshold="+str(threshold), 0, 1, 'L')

            # print out the high issues
        for i in red_dates:
            start_burst=i.strftime('%Y-%m-%d %H:%M')
            if start_burst=='2020-01-01 00:00':
                break
            j=i+timedelta(hours=1)
            end_burst=j.strftime('%Y-%m-%d %H:%M')
            pdf.set_font("Arial", 'B', size = 11)
            pdf.cell(100, H, 'Event burst between '+start_burst+'-'+end_burst, 0, 1, 'L')

            cmd="SELECT count(*), service_name, alerts FROM public.cppm_alerts WHERE timestamp>='{}' AND timestamp<'{}' AND alerts NOT LIKE '{}' GROUP BY service_name, alerts ORDER BY count DESC".format(start_burst,end_burst,whitelist)
#            print(cmd)
            cur.execute(cmd)

            row = cur.fetchone()
               # row[0] count
               # row[1] service_name
               # row[2] alert message
            pdf.cell(25, h, "Count", 0, 0, 'L')
            pdf.cell(30, h, "Service", 0, 0, 'L')
            pdf.cell(200, h, "Alert", 0, 1, 'L', )

            pdf.set_font("Arial", size = 11)
            while row is not None:
                if DEBUG:
                    print('Row=',row)
                if row[0]<threshold:
                    break
                pdf.cell(25, H, str(row[0]), 0, 0, 'L')
                if ANON_CPPM:
                    name,ANON_CPPM_NO=get_anonymous_name(row[1], ANON_CPPM_DIC, ANON_CPPM_NO, 'AnonCPPM')
                else:
                    name=row[1]
                pdf.cell(30, H, name, 0, 0, 'L')

                name=row[2]
                if replace1:
                    name=name.replace(replace1,'XXX')
                if replace2:
                    name=name.replace(replace2,'YYY')
                if replace3:
                    name=name.replace(replace3,'ZZZ')
                pdf.multi_cell(200, H, name, 0, 'L')
                pdf.ln(1)
                row = cur.fetchone()
            pdf.ln(H)
            
        if whitelist:
            pdf.ln('')
            pdf.cell(0, H, comment2+"Alert Whitelist '"+whitelist+"'", 0, 1, 'L')

    except (Exception) as error:
        print(error)
    finally:
        pdf.ln(2*h)
        if DEBUG:
            print('Leaving alerts_burst_details')



if __name__ == '__main__':

    FILE_INDEX=0
    print('Welcome to ClearPass Operational Report')

#    now=datetime.today()
#    expire=datetime.strptime(EXPIRE, '%Y-%m-%d')
#    print('WARNING: This code will expire on ',expire)
#    if now>expire:
#        print('The code has expired')
#        sys.exit(0)

    today=date.today()
    end_time=today-timedelta(days=1)
    END=end_time.strftime("%Y-%m-%d")
    argc=len(sys.argv)
    if argc>3:
        raise ValueError('Usage: python report.py [-D] [-d|-w|-m], where -D=debug, -d=yesterday, -w=last week, -m=last month, defaults to yesterday or time set in report.ini')
        sys.exit()
    elif argc==1:   # ie report with no parameters
        start_time=today-timedelta(days=2)
    elif argc==2:    # ie report -D or report [-d|-w|-m]
        if sys.argv[1]=='-D':
            DEBUG=True
            start_time=today-timedelta(days=2)
        elif sys.argv[1]=='-d':
            start_time=today-timedelta(days=2)
        elif sys.argv[1]=='-w':
            start_time=today-timedelta(days=8)
        elif sys.argv[1]=='-m':
            start_time=today-timedelta(days=29)
        else:
            raise ValueError('Usage: python report.py [-D] [-d|-w|-m], where -D=debug, -d=yesterday, -w=last week, -m=last month, defaults to yesterday or time set in report.ini')
            sys.exit()
    elif argc==3:    # ie report -D [-d|-w|-m]
        if sys.argv[1]=='-D':
            DEBUG=True
        else:
            raise ValueError('Usage: python report.py [-D] [-d|-w|-m], where -D=debug, -d=yesterday, -w=last week, -m=last month, defaults to yesterday or time set in report.ini')
            sys.exit()
        if sys.argv[2]=='-d':
            start_time=today-timedelta(days=2)
        elif sys.argv[2]=='-w':
            start_time=today-timedelta(days=8)
        elif sys.argv[2]=='-m':
            start_time=today-timedelta(days=29)
        else:
            raise ValueError('Usage: python report.py [-D] [-d|-w|-m], where -D=debug, -d=yesterday, -w=last week, -m=last month, defaults to yesterday or time set in report.ini')
            sys.exit()
    START=start_time.strftime("%Y-%m-%d")

# read connection parameters
#    print("Read config")
     
#    configpath='./report_creds.ini'
#    key_env = 'CPOR_INI_KEY'
#    if os.path.isfile(configpath):
#              # Read the details
#         scfg = SecureConfigParser.from_env('CPOR_INI_KEY')
#         scfg.read(configpath)
#         password = scfg.get('credentials', 'password')
#    else:          # Record the details
#         print('Welcome to ClearPass Operational Report')
#         print('Please enther the appexternal\'s password:')
#         pwd = input()
#         scfg.set('credentials', 'password', 'better_password', encrypt=True)
#         scfg.set('credentials', 'password', password, encrypt=True)
#         print('Password=',password)
#         fh=open(configpath, 'w')
#         scfg.write(fh)
#         fh.close()
#    sys.exit()


    params = configdb('report.ini', 'report')

    if 'start' in params:
        value=params['start']
        if value!='':
            START=value
            start_time=datetime.strptime(START, '%Y-%m-%d')
    if 'end' in params:
        value=params['end']
        if value!='':
            END=value
            end_time=datetime.strptime(END, '%Y-%m-%d')
    print('Duration ', START, '<', END)
    if START>=END:
        print('Error: end date must be larger than start date')
        sys.exit(1)
    delta=end_time-start_time
    if delta.days <= 0:
        print('Error: end date must be larger than start date')
        sys.exit(1)
    if 'author' in params:
        author=params['author']
    else:
        print('Please enter the author\'s name: ', end='')
        author = input()
    if 'title' in params:
        title=params['title']
    else:
        print('Error: report.ini must include an title field')
        sys.exit(2)
    if 'timeframe' in params:
        timeframe=params['timeframe']
    else:
        print('Error: report.ini must include an timeframe field')
        sys.exit(2)
    if 'ignore' in params:
        IGNORE=params['ignore']

    anonymous_setup()

    detail=title+' Detail'
    pdf = FPDF(orientation='L', unit='mm', format='A4')
    pdf.set_title(detail)
    pdf.set_author(author)
    pdf.add_page()
    pdf.set_font("Arial", 'B', size = 24)
    pdf.cell(0, h*2, detail, 0, 1, 'C')
    pdf.set_font("Arial", 'B', size = 12)
    pdf.cell(0, h, author, 0, 1, 'C')
    today = date.today()
    today_str= today.strftime("%d/%m/%y")
    pdf.cell(0, h, today_str, 0, 1, 'C')
    pdf.cell(0, h, VERSION, 0, 1, align='C')
    duration = timeframe+' '+START+' to '+END
    pdf.cell(0, h, duration, 0, 1, align='C')
    pdf.cell(0, h, "", 0, 1, align='C')

    contents()

#    print("Open connection")
    conn=connect()
    if conn is None:
        print('Failed to connect to the ClearPass postgresql database')
        sys.exit(0)
    print('Connection open')

        # Read the ClearPass in the customer's cluster
    pdf.add_page(orientation='L')
       # Generate the detailed report
    pdf.set_font("Arial", 'B', size = 20)
    pdf.cell(0, h, "Specific Details", 0, 1, 'L')
    print('Specfic Details')

    value=cluster_load_distribution(conn, pdf)

    if value==False:
        print('ERROR: Not finding any active cluster members!')
        print('\tAre the dates right?')
        sys.exit(0)

    events(conn, pdf)
    red_dates=events_graph(conn, pdf)
    events_burst_details(conn,pdf,red_dates)
     
    license(conn, pdf)

    endpoint_categories(conn, pdf)
    endpoint_IP_assign(conn, pdf)
    endpoint_addr_schema(conn, pdf)
    endpoint_random(conn, pdf)
    endpoint_spoof(conn, pdf)
    endpoints_missing_details(conn, pdf)

    pdf.add_page(orientation='L')
    auths_per_service(conn, pdf)

    pdf.add_page(orientation='L')
    fails_per_service(conn, pdf)

#--     success_per_service(conn, pdf)

    pdf.add_page(orientation='L')
    red_list = null_service(conn, pdf)

    if len(red_list)>0:
        endpoints_auth_null_graph(conn, pdf, 'Top Endpoints not Matching a Service', red_list[:3])

    pdf.add_page(orientation='L')
    red_list = wired_endpoint_auths(conn, pdf)
    if len(red_list) > 0:
        count=1
        for mac in red_list:
            wired_endpoint_details(conn, pdf, mac)
            if count==3:
               break
            count+=1
        endpoints_auth_graph(conn, pdf, 'Top Wired Endpoints Auths', red_list[:3])
         
    pdf.add_page(orientation='L')
    red_list = wired_endpoint_auths_burst(conn, pdf, red_list[:3])
    if len(red_list)>0:
        endpoints_auth_graph(conn, pdf, 'Top Wired Burst Authentications per hour', red_list[:3])
          

    pdf.add_page(orientation='L')
    red_list = wireless_endpoint_auths(conn, pdf)
    if len(red_list) > 0:
        count=1
        for mac in red_list:
            wireless_endpoint_details(conn, pdf, mac)
            if count==3:
                break
            count+=1
        endpoints_auth_graph(conn, pdf, 'Top Wireless Endpoints Auths', red_list[:3])
          
    pdf.add_page(orientation='L')
    red_list = wireless_endpoint_auths_burst(conn, pdf, red_list[:3])
    if len(red_list)>0:
        endpoints_auth_graph(conn, pdf, 'Top Wireless Burst Authentications per hour', red_list[:3])

    pdf.add_page(orientation='L')
    red_list = virtual_user_auths(conn, pdf)
    if len(red_list) > 0:
        count=1
        for username in red_list:
            virtual_user_details(conn, pdf, username)
            if count==3:
                break
            count+=1
        users_auth_graph(conn, pdf, 'Top Virtual User Auths', red_list[:3])

    pdf.add_page(orientation='L')
    red_list = virtual_user_auths_burst(conn, pdf, red_list[:3])
    if len(red_list)>0:
        users_auth_graph(conn, pdf, 'Top Virtual Burst Authentications per hour', red_list[:3])

    pdf.add_page(orientation='L')
    red_list = dot1x_auths(conn, pdf)
    if len(red_list) > 0:
        count=1
        for username in red_list:
            virtual_user_details(conn, pdf, username)
            if count==3:
                break
            count+=1
        users_auth_graph(conn, pdf, 'Top 802.1X Users', red_list[:3])

    pdf.add_page(orientation='L')
    nas_most_auths(conn, pdf)
    nas_least_auths(conn, pdf)

    pdf.add_page(orientation='L')
    red_list = failed_authorization(conn, pdf)

    pdf.add_page(orientation='L')
    red_list=dot1x_user_multi_devices(conn, pdf)
#--    if len(red_list) > 0:
#--        count=1
#--        for mac in red_list:
#--            dot1x_user_multi_devices_detail(conn, pdf, mac)
#--            if count==3:
#--                break
#--            count+=1

    pdf.add_page(orientation='L')
    red_list=dot1x_device_multi_users(conn, pdf)
#--    if len(red_list) > 0:
#--        count=1
#--        for mac in red_list:
#--            dot1x_device_multi_users_detail(conn, pdf, mac)
#--            if count==3:
#--                break
#--            count+=1

    pdf.add_page(orientation='L')
    red_list=wired_device_moves(conn, pdf)
#--    if len(red_list) > 0:
#--        count=1
#--        for mac in red_list:
#--            wired_device_moves_details(conn, pdf, mac)
#--            if count==3:
#--                break
#--            count+=1

    pdf.add_page(orientation='L')
    red_list=wifi_device_ssid_moves(conn, pdf)
#--    if len(red_list) > 0:
#--        count=1
#--        for mac in red_list:
#--            wifi_device_ssid_moves_details(conn, pdf, mac)
#--            if count==3:
#--                break
#--            count+=1

    pdf.add_page(orientation='L')
    red_list=tacacs_auths(conn, pdf)
#--    if len(red_list) > 0:
#--        for user in red_list:
#--            if ANON_USER:
#--                username=ANON_USER_DIC[username]
#--            tacacs_auth_details(conn, pdf, user)
#--            tacacs_auth_graph(conn, pdf, user)

    pdf.add_page(orientation='L')
    device_session_duration(conn, pdf)

    pdf.add_page(orientation='L')
    device_session_data(conn, pdf)

    pdf.add_page(orientation='L')
    device_session_data_tx(conn, pdf)

    pdf.add_page(orientation='L')
    device_session_data_rx(conn, pdf)

#-- Is there any point in getting the summation of a user's devices?
#--     print('\tTop User Sessions Total Duration ')
#--     user_sessions_duration(conn, pdf)
#--
#--     pdf.add_page(orientation='L')
#--     print('\tTop User Sessions Total Data ')
#--     user_sessions_data(conn, pdf)
#--
#--     pdf.add_page(orientation='L')
#--     print('\tTop User Sessions Transmitted Data ')
#--     user_sessions_data_tx(conn, pdf)
#--
#--     pdf.add_page(orientation='L')
#--     print('\tTop User Sessions Received Data ')
#--     user_sessions_data_rx(conn, pdf)

    print('\tGuests - what reports should I do?')
    
    pdf.add_page(orientation='L')
    audit(conn, pdf)
    
    pdf.add_page(orientation='L')
    onguard_summary(conn, pdf)
    onguard_failed(conn, pdf)

#--    alerts(conn, pdf)
#--    red_dates=alerts_graph(conn, pdf)
#--    alerts_burst_details(conn,pdf,red_dates)
       
    print('\tPrint Detailed Report ', str(datetime.now()))
    pdf.output(detail+'.pdf')

    summary=title+' Summary'
    pdfs = FPDF(orientation='P', unit='mm', format='A4')
    pdfs.set_title(summary)
    pdfs.set_author(author)
    pdfs.add_page()
    pdfs.set_font("Arial", 'B', size = 20)
    pdfs.cell(0, h*2, summary, 0, 1, 'C')
    pdfs.set_font("Arial", size = 11)
    pdfs.cell(0, h, author, 0, 1, 'C')
    today = date.today()
    today_str= today.strftime("%d/%m/%y")
    pdfs.cell(0, h, today_str, 0, 1, 'C')
    pdfs.cell(0, h, VERSION, 0, 1, align='C')
    duration = 'Time Frame '+START+' to '+END
    pdfs.cell(0, h, duration, 0, 1, align='C')
    pdfs.cell(0, h, "", 0, 1, align='C')
    pdfs.add_page(orientation='P')
    print('Executive Summary')
    pdfs.set_font("Arial", 'B', size = 20)
    pdfs.cell(0, h, "Executive Summary", 0, 1, 'P')
    cluster_auths(conn, pdfs)
    events_graph(conn, pdfs)
    max_license(conn, pdfs)
    endpoint_status(conn, pdfs)
    endpoints_missing(conn, pdfs)

    recommendations(conn, pdfs)

    anonymous_output()

    print('\tPrint Summary Report ', str(datetime.now()))
    pdfs.output(summary+'.pdf')
    if conn is not None:
        conn.close()
    print('Finished')

