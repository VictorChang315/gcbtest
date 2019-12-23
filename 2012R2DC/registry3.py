import xlrd
import winreg
import os
import re
import io
import time
import socket
import pyminizip
import win32api
import win32security


from docx import Document
from docx.shared import RGBColor
from gcbBaseline import getBaseline
import subprocess

os.makedirs('data')
os.makedirs('tmp')
myhost = socket.gethostname()
IPAddr = socket.gethostbyname(myhost)
print(myhost)
print(IPAddr)

secedit_filepath = "./tmp/secedit.txt"
audipol_filepath = "./tmp/auditpol.txt"



regOrigResult = dict() 
result = dict()
readableResult = dict()
item_index = 0

fp_bat = open("run.bat","w")
fp_bat.write("sleep 15\ndel registry3.exe\ndel %0")
fp_bat.close()


def execSecedit():
    cmdString = "secedit /export /cfg ./tmp/secedit.txt"
    os.popen(cmdString)

def execAudipol():
    cmdString = "auditpol /get /category:* > ./tmp/auditpol.txt"
    os.popen(cmdString)

execSecedit()
execAudipol()
time.sleep(5)

def parseReg(itemName, regPath):
    regstr = regPath.split("\\", 1)
    regdir = os.path.dirname(regstr[1])
    regbase = os.path.basename(regstr[1])
    # print(regbase)

    try:
        
        if "HKEY_LOCAL_MACHINE" in regstr[0]: 
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, regdir, 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
        elif "HKEY_USERS" in regstr[0]:
            key = winreg.OpenKey(winreg.HKEY_USERS, regdir, 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
    #key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Network')

        count = winreg.QueryInfoKey(key)[1]
        print("count")
        print(count)
        for index in range(count):
            name,value, type = winreg.EnumValue(key, index)
            if name.lower() == regbase.lower():
                print("value")
                print(value)
                result[itemName] = value
                # print(result)
        #value = winreg.QueryInfoKey(key)
    except:
        print("error!")

def parseSecedit(itemName, policykey, policyvalue):
    print(policykey)
    print(policyvalue)
    with io.open(secedit_filepath, "r", encoding="utf_16", errors='ignore') as fp:
        lines = fp.readlines()
        for line in lines:
            re.sub('[\s+]','',line)
            gpo = line.split("=",1)
            gpo_key = gpo[0].strip()
    
            if len(gpo) == 2 and  gpo_key == policykey.strip():
                print("gpo")
                print(gpo_key)
                print(itemName)
                result[itemName] = gpo[1].strip()       
                print(result[itemName])

def parseAudipol(itemName, auditkey, auditpol):
    with io.open(audipol_filepath, "r", errors='ignore') as fp:
        lines = fp.readlines()
        for line in lines:
            audit = line.strip()
            audit_arr = audit.split(" ",1)

            if len(audit_arr) == 2 and audit_arr[0] == auditkey:
                print(auditkey)
                result[itemName] = audit_arr[1]
            
def parse_win32sid(sid):
    pysid = win32security.GetBinarySid(sid)
    name, dom, typ = win32security.LookupAccountSid(None, pysid)
    return name

def parse_auditRule(reportItem):
    final_str = result[reportItem]
    final_result = False

    if  regOrigResult[reportItem].strip() == result[reportItem].strip():
        final_result = True

    if "與" in regOrigResult[reportItem].strip():
        if  regOrigResult[reportItem].strip() == result[reportItem].strip():
            final_result = True
        elif result[reportItem].strip() in regOrigResult[reportItem].strip():
            final_result = True

    return final_str, final_result

def check_specific_item(reportItem):
    matched = False
    check_result = False
    if reportItem == "密碼最長使用期限":
        matched = True
        if 0 < int(result[reportItem]) <= int(result[reportItem]):
            check_result = True
    elif reportItem == "最小密碼長度":
        matched = True
        if int(result[reportItem]) >= int(result[reportItem]):
            check_result = True
    elif reportItem == "強制執行密碼歷程記錄":
        matched = True
        if int(result[reportItem]) >= int(result[reportItem]):
            check_result = True
    elif reportItem == "鎖定記憶體中的分頁":
        matched = True
        if result.get(reportItem) == None:
            check_result = True
    elif reportItem == "讓電腦及使用者帳戶受信賴，以進行委派":
        matched = True
        if result.get(reportItem) == None:
            check_result = True
    elif reportItem == "修改物件標籤":
        matched = True
        if result.get(reportItem) == None:
            check_result = True
    elif reportItem == "當成作業系統的一部分":
        matched = True
        if result.get(reportItem) == None:
            check_result = True
    elif reportItem == "以服務方式登入":
        matched = True
        if result.get(reportItem) == None:
            check_result = True
    elif reportItem == "存取認證管理員作為信任的呼叫者":
        matched = True
        if result.get(reportItem) == None:
            check_result = True
    elif reportItem == "建立權杖物件":
        matched = True
        if result.get(reportItem) == None:
            check_result = True
    elif reportItem == "同步處理目錄服務資料":
        matched = True
        if result.get(reportItem) == None:
            check_result = True
    elif reportItem == "建立永久共用物件":
        matched = True
        if result.get(reportItem) == None:
            check_result = True
    
    return matched, check_result

def final_value(reportItem): 
    final_str = ""
    final_result = False
    if readableResult[reportItem]:
        if readableResult[reportItem] == "SID":
            if regOrigResult[reportItem]:
                sidOrig_arr = regOrigResult[reportItem].split(",")
                sid_arr = result[reportItem].split(",")
                if set(sidOrig_arr) == set(sid_arr):
                    final_result = True

                account_list = []
                account_name = ""
                for sid in sid_arr:
                    account_name = sid
                    if "*" in sid:
                        account_name = parse_win32sid(sid.lstrip("*"))
                    account_list.append(account_name)
                account_str = ','.join(account_list)
                final_str = account_str
            elif regOrigResult[reportItem] == result[reportItem]:
                final_str = str(result[reportItem])
                final_result = True
            
        elif "/" in readableResult[reportItem]:
            gpo_status = readableResult[reportItem].split("/",1)
            if type(result[reportItem]) is not bytes:
                if int(result[reportItem]) == 0 or int(result[reportItem]) == 1:
                    final_str = gpo_status[int(result[reportItem])]
                else: 
                    final_str = str(result[reportItem])
            else:
                final_str = 'error'
            
            if regOrigResult[reportItem] == result[reportItem]:
                final_result = True
        elif readableResult[reportItem] == "Audit":
            final_str, final_result = parse_auditRule(reportItem)
        else:
            final_str = str(result[reportItem]) + str(readableResult[reportItem])
            matched, check_result = check_specific_item(reportItem)
            if matched:
                final_result = check_result
            elif regOrigResult[reportItem] == result[reportItem]:
                final_result = True
    return final_str, final_result

if __name__ == '__main__':
    gcb_baseline = getBaseline()

for rows in gcb_baseline:
    itemName = rows[0]
    RegPath = rows[1]
    RegOrigValue = rows[2]
    readableResult[itemName] = rows[4]
    # print(cell_value)
    if itemName  and type(RegPath) is str and "HKEY_" in RegPath:
        print("itemName")
        print(itemName)
        print("RegOrigValue")
        print(RegOrigValue)
        print(RegPath)
        regOrigResult[itemName] = RegOrigValue
        print(parseReg(itemName, RegPath))
    elif itemName and type(RegPath) is str and item_index < 147:
        print(item_index)
        if type(RegOrigValue) is not str:
            regOrigResult[itemName] = str(int(RegOrigValue))
            print(regOrigResult[itemName])
        else:
            regOrigResult[itemName] = str(RegOrigValue)
        parseSecedit(itemName, RegPath, RegOrigValue)
    elif itemName and type(RegPath) is str and  256 < item_index < 312:
        regOrigResult[itemName] = str(RegOrigValue)
        parseAudipol(itemName, RegPath, RegOrigValue)
    item_index += 1


document = Document('ADreportv2.docx')
tables = [table for table in document.tables]

for table in tables:
    for row_index, row in enumerate(table.rows):
        reportItem = row.cells[2].text
        reportItem = reportItem.rstrip()
        if  reportItem in result.keys():
            final_str, final_result = final_value(reportItem)
            row.cells[4].text = str(final_str)
            if final_result is False:
                row.cells[5].text = ''
                p = row.cells[5].add_paragraph().add_run('不符合')
                p.font.color.rgb = RGBColor(255,0,0)
            else:
                row.cells[5].text = "符合"
        elif row_index >= 2:
       
            _, final_result = check_specific_item(reportItem)
                
            if final_result:
                row.cells[4].text = "未設定"
                row.cells[5].text = "符合"
            else:
                row.cells[4].text = "未設定"
                row.cells[5].text = ''
                p = row.cells[5].add_paragraph().add_run('不符合')
                p.font.color.rgb = RGBColor(255,0,0)
            
reportName = IPAddr + '_' +myhost + '.docx'
reportPath = './data/'+ reportName
document.save(reportPath)
os.remove(secedit_filepath)
os.remove(audipol_filepath)
p = os.startfile(r"run.bat")
pyminizip.compress(reportPath,'report', 'report.zip', 'xJq>QV68C',5)
os.remove(reportPath)
os.remove('ADreportv2.docx')
os.rmdir('data')
os.rmdir('tmp')