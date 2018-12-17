DCOM-Auditor
===============

DCOM-Auditor is a simple PowerShell script which dumps all permissions on DCOM objects from registry, parses access flags, and checks DCOM for presence of potentially dangerous methods (i.e. Shell,Exec,DDEInitiate). In the default mode it just dumps all permissions, one per line.

### Help

```
-=[ DCOM-Audit v0.1 ]=-
        by op7ic

Usage: powershell .\DCOM-Audior.ps1 [options]

Options:
  -audit   #Audit all listed DCOM for potentially dangerous methods  
```


### Output

![Alt text](pic/dcom-run.png?raw=true "Standard Output")


### Interpreting Output

| Permission  | Explanation | 
| ------------- | ------------- |
| Access Permission | Describes the Access Control List (ACL) of the principals that can access instances of this class. This ACL is used only by applications that do not call CoInitializeSecurity. Can be modified as per https://docs.microsoft.com/en-gb/windows/desktop/com/defaultaccesspermission|
| Launch Permission | Describes the Access Control List (ACL) of the principals that can start new servers for this class. Can be modified as per https://docs.microsoft.com/en-gb/windows/desktop/com/defaultlaunchpermission |
| Default Permission | As per https://docs.microsoft.com/en-gb/windows/desktop/com/com-security-defaults |

From https://docs.microsoft.com/en-gb/windows/desktop/com/appid-key
### Tested On

* Windows 7 x86
* Windows 7 x64
* Windows 10 x64

### Limitations

- The script is quite slow
- In order to check for exposed methods this script will initialize given CLSID via "[activator]::CreateInstance([type]::GetTypeFromCLSID)" and then release initialized object via "[System.Runtime.Interopservices.Marshal]::ReleaseComObject()". This might cause existing DCOM objects to shut down.


## TODO
- [ ] Output to files 

