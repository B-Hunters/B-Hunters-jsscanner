from .__version__ import __version__
import subprocess
import json
import os
from urllib.parse import urlparse
from b_hunters.bhunter import BHunters
from karton.core import Task
import re
from bson.objectid import ObjectId

class jsscanner(BHunters):
    """
    JS scanner developed by 0xBormaa
    """

    identity = "B-Hunters-jsscanner"
    version = __version__
    persistent = True
    filters = [
        {
            "type": "js", "stage": "new"
        }
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
    def search_file_from_url(self,url):
        try:
            curl_process = subprocess.Popen(["curl", "-s", url], stdout=subprocess.PIPE)

            # Call grep command to search for the pattern in the output of curl
            grep_process = subprocess.Popen(["grep", "-E", "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret|smtp"], stdin=curl_process.stdout, stdout=subprocess.PIPE, text=True)

            # Capture the output
            output, _ = grep_process.communicate()
            return output
        except Exception as e:
            self.log.error(f"Error occurred while fetching content: {str(e)}")

        return None

    def checkjs(self,url):
        try:
            result=[]
            # tempres=search_file_from_url(url)
            # if tempres and tempres !="":
            #     result.append(tempres)  

            filename=self.generate_random_filename()
            jsfile=self.generate_random_filename()+".js"
            # self.log.info(f"Starting nuceli {url}")
            # output=subprocess.run(["nuclei","-tags","config,keys,token,key,api,secret","-t","/app/service/nuclei-templates/","-target", url,"-o",filename], capture_output=True, text=True)
            # output=subprocess.run(["curl","-s",url,"-o",jsfile], capture_output=True, text=True)

            # outputnipe=subprocess.run(["nipejs","-d",jsfile], capture_output=True, text=True)
            # nipedata=outputnipe.stdout.split("\n")
            # for i in nipedata:
            #     if i !="":
            #         result.append(i)
            # self.log.info(f"Starting SecretFinder {url}")

            outputsecret=subprocess.run(["python3","/app/service/secretfinder/SecretFinder.py","-i",url,"-o","cli"], capture_output=True, text=True)
            secretdata=outputsecret.stdout.split("\n")
            if len(secretdata)>2:
                for i in range(len(secretdata)):
                    if i !=0 and i !=len(secretdata)-1 and len(secretdata[i])<120 and len(secretdata[i])>10 and '"}))' not in secretdata[i] and '000000' not in secretdata[i] and 'fi' not in secretdata[i].lower() and ':!' not in secretdata[i].lower() and 'word"' not in secretdata[i].lower() and 'void' not in secretdata[i].lower() and 'var' not in secretdata[i].lower()  and 'else' not in secretdata[i].lower() and 'janfeb' not in secretdata[i].lower() and 'april_may' not in secretdata[i].lower() and 'if' not in secretdata[i].lower() and 'let' not in secretdata[i].lower() and 'invalid' not in secretdata[i].lower() and 'aaaa' not in secretdata[i].lower() and '[input]' not in secretdata[i].lower() and 'error' not in secretdata[i].lower()  and 'yield' not in secretdata[i].lower() and 'twilio' not in secretdata[i].lower()  and 'authorization_basic' not in secretdata[i].lower() and 'heroku' not in secretdata[i].lower() and 'authorization_api' not in secretdata[i].lower() and 'password' not in secretdata[i].lower() and 'google_captcha' not in secretdata[i].lower() and '})' not in secretdata[i] and '){' not in secretdata[i]:
                        text=secretdata[i].replace("\t->\\", ":")
                        result.append(text)



            # datanulcei=""
            # if os.path.exists(filename) and os.path.getsize(filename) > 0:  # Check if file exists and is not empty
            #     with open(filename, 'r') as file:
            #         try:
            #             datanulcei = file.read()
            #         except Exception as e:
            #             print("Error:",e)
            #             # result=""
            # if datanulcei!="":
            #     nucleiarr=datanulcei.split("\n")
            #     for i in nucleiarr:
            #         result.append(i)
        except Exception as e:
            self.log.error(e)
        return result
                    
    def scan(self,url):
        result=[]
        result=self.checkjs(url)
        if result !=[]:
            return result
        return []
        
    def process(self, task: Task) -> None:
        url = task.payload["file"]
        domain = task.payload["subdomain"]
        report_id=task.payload_persistent["report_id"]
        self.log.info("Starting processing new url")
        self.update_task_status(url,"Started")
        js_url_match = re.search(r'(\S+\.js)\b', url)

        if js_url_match:
            js_url = js_url_match.group(1)
            url=js_url
            

        self.log.warning(url)
        self.waitformongo()
        db=self.db
        collection = db["js"]
        
        existing_document = collection.find_one({"report_id":ObjectId(report_id),"url": url})
        resultarr=[]
        if existing_document is None:
            new_document = {"report_id":ObjectId(report_id),"domain": domain, "url": url,"Vulns":[], "nuclei":False}
            result=self.scan(url)
            
            for i in result:
                resultdata=i.split("\t->\t")

                if "google_captcha" not in resultdata[0] and "square_access_token" not in resultdata[0]:
                    resultarr.append(i)

            if resultarr !=[]:
                new_document["Vulns"]=resultarr
                results = "\n".join(resultarr)
                self.send_discord_webhook("Js Scanner Result "+url,results,"main")
            collection.insert_one(new_document)
        else:
            self.log.info(f"{url} Found")
            
        self.update_task_status(url,"Finished")