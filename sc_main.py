#!/usr/bin/env python
#coding: utf-8

import json
import requests
import requests.packages.urllib3 as urllib3
import datetime
import time


urllib3.disable_warnings()

class APIError(StandardError):
    def __init__(self, error_code, error, request=None):
        self.error_code = error_code
        self.error = error
        self.request = request
        StandardError.__init__(self, error)

    def __str__(self):
        return 'APIError, error_num: %s, error_message %s, request: %s' % (self.error_code, self.error, self.request)

class ScClient(object):
    def __init__(self, server,username, password, port=443,access_api_type=[], verify_ssl=False):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.access_api_type = access_api_type
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.token = self.__get_token()
        self.headers = {"Content-Type": "application/json", "X-SecurityCenter": str(self.token)}
        
    def __get_token(self):
        headers = {
            "Content-Type": "applicathon/json",
        }
        data = json.dumps({"username": self.username, "password": self.password})
        rv = self.http_call('post', 'token', headers, args=data)
        return rv['response']['token']

    def http_call(self, method, resource, headers, args=None, format_to_json=True, **kwargs):
        args_keyword_map = {'get': 'params', 'post': 'data','patch': 'data'}
        kwargs.update({'headers': headers})
        if args:
            kwargs.update({args_keyword_map.get(method): args})
        kwargs['verify'] = self.verify_ssl
        url = "https://{0}:{1}/rest/{2}".format(self.server, self.port,resource)
        r = getattr(self.session, method)(url, **kwargs)

        if r.status_code != 200:
            r.raise_for_status()
        if format_to_json:
            try:
                result = r.json()
                if result['error_code'] != 0:
                    raise APIError(result['error_code'], result['error_msg'], url)
            except ValueError, e:
                raise APIError(r.status_code, 'SC API return error json object', url)
            return result
        return r.text


    def __repr__(self):
        return "{0} Client.".format(self.username)


class scanner(ScClient):
    def ActiveScan(self):
        now = datetime.datetime.now()
        createdTime = int(time.mktime(now.timetuple()))
        startTime = createdTime + 5
        #查看扫描结果及状态
        data = {
            "filter":"usable",
            "fields":"canUse,canManage,owner,groups,ownerGroup,status,name,createdTime,schedule,policy,plugin,type"
        }
        results = self.http_call('get','scan',headers=self.headers,args=data)
        for result in results.get('response').get('usable'):
            name = result.get('name')
            scanid = result.get('id')
            print name,scanid
        #     test = SecurityCenter.objects.filter(scan_name=name).exists()
        #     print test

        #更新扫描任务信息

        iplist ="hostip"


        values ={
            "repository":{"id":1},
            "schedule":{"start":"TZID=Asia/Hong_Kong:20171027T193000","repeatRule":"FREQ=TEMPLATE;INTERVAL=1","type":"template"},
            "policy":{"id":"1000001"},
            "ipList":iplist,
            "assets":[],
            "plugin":{"id":-1}
        }
        values = json.dumps(values)
        id = 6
        resource = 'scan/%d' %id
        result=self.http_call('patch',resource,headers=self.headers,args=values)

        #执行扫描任务
        name = 'test'
        values = {
            "id":id,
            "name":name,
            "description":"",
            "context":"",
            "status":0,
            "createdTime":createdTime,
            "startTime":startTime,
            "group":
                {"id":0,"name":"Administrator"},
            "repository":{},
            "schedule":{"start":"TZID=:Invalid dateInvalid date","repeatRule":"FREQ=TEMPLATE;INTERVAL=","type":"template"},
            "dhcpTracking":"false",
            "emailOnLaunch":"false",
            "emailOnFinish":"false",
            "type":"policy",
            "policy":{"id":"1000001"},
            "plugin":
                {"id":-1,"name":"","description":""},
            "zone":{"id":-1},
            "scanningVirtualHosts":"false",
            "classifyMitigatedAge":0,
            "assets":[],
            "ipList":""
        }
        values = json.dumps(values)
        resource = 'scan/%d/launch' %id
        result=self.http_call('post',resource,headers=self.headers,args=values)


        jobid =12
        #暂停扫描任务
        data = {
            "id":jobid,
            "name":"test",
            "status":"Pausing",
        }
        data = json.dumps(data)
        #resource = 'scanResult/12/pause'
        #result=self.http_call('post',resource,headers=self.headers,args=data)

        #继续执行任务
        data = {
            "id":jobid,
            "name":"test",
            "status":"Resuming"
        }
        data = json.dumps(data)
        #resource = 'scanResult/jobid/resume'
        #results =self.http_call('post',resource,headers=self.headers,args=data)

    def ScanResultsId(self):
        data = {
            "filter":"usable",
            "fields":"canUse,canManage,owner,groups,ownerGroup,status,name,details,diagnosticAvailable,importStatus,createdTime,startTime,finishTime,importStart,importFinish,running,totalIPs,scannedIPs,completedIPs,completedChecks,totalChecks,downloadAvailable,downloadFormat,repository,resultType,resultSource,scanDuration"
        }

        results = self.http_call('get','scanResult',headers=self.headers,args=data)

        jobid_list = {
            'Partial':[],
            'Completed':[],
            'Pausing':[],
            'Paused':[]
        }
        for result in results.get('response').get('usable'):
            scanname = result.get('name')
            jobid = result.get('id')
            status = result.get('status')
            description = result.get('description')
            completedChecks = result.get('completedChecks')
            totalChecks = result.get('totalChecks')
            print scanname,jobid


            percent = '%.2f%%' %(float(completedChecks)/float(totalChecks)*100)

            # info = SecurityCenter(jobID=jobid,scan_name=scanname,scan_status=status,percent=percent)
            # info.save()

            # if name == self.ActiveScan():
            #     pass
            if status == 'Completed':
                jobid_list.get('Completed').append(jobid)
            if status == 'Partial':
                jobid_list.get('Partial').append(jobid)
            if status == 'Paused':
                jobid_list.get('Paused').append(jobid)
            if status == 'Pausing':
                jobid_list.get('Pausing').append(jobid)
        print jobid_list



if __name__ == '__main__':
    s = scanner('hostip', 'user', 'password')
    # s.getid()
    # s.ScanResultsId()
    # s.ActiveScan()
    s.ScanResultsId()


