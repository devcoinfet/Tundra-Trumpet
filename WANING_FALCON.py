# encoding=utf8
import sys
from urllib2 import urlopen, URLError
from argparse import ArgumentParser
from bs4 import BeautifulSoup
#https://codereview.stackexchange.com/questions/60769/scrape-an-html-table-with-python used allot of his parsing code customized for bgpstream 


def parse_rows(rows):
    """ Get data from rows """
    results = []
    for row in rows:
        table_headers = row.find_all('th')
        if table_headers:
            results.append([headers.get_text() for headers in table_headers])

        table_data = row.find_all('td')
        if table_data:
            results.append([data.get_text() for data in table_data])
    return results


def one_up_top():
    asnum_list =[]
    events = []
   
    try:
        resp = urlopen('https://bgpstream.com/')
    except URLError as e:
        print 'An error occured fetching %s \n %s' % (url, e.reason)   
        return 1
    soup = BeautifulSoup(resp.read(),'lxml')

    # Get table
    try:
        table = soup.find('table')
    except AttributeError as e:
        print 'No tables found, exiting'
        return 1

    # Get rows
    try:
        rows = table.find_all('tr')
    except AttributeError as e:
        print 'No table rows found, exiting'
        return 1

    # Get data
    table_data = parse_rows(rows)

    # Print data
    for i in table_data:
        for items in i:
            start = '(AS'
            end = ')'
            reason = i[0].encode('utf-8').strip().lstrip()
            data1 = i[2].encode('utf-8').strip().lstrip()
            try:
               data2 = data1.split(start)[1].split(end)[0].lstrip()
               asnum_list.append(data2)
            except:
                pass
            
            if data2:
               bgp_data = {'Event_Reason':reason,'Data':data1,'AS#':data2}
               events.append(bgp_data)
            else:
               bgp_data = {'Event_Reason':reason,'Data':data1} 
               events.append(reason)

               



    
            
    print("Amount Of Events:"+str(len(events)))
    for situations in events:
        print(repr(situations).encode("utf-8")+"\n").lstrip()
        
    return asnum_list,events
     
