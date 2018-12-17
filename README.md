DCOM-Auditor
===============

DCOM-Auditor is a simple PowerShell script which dumps all permissions on DCOM objects from registry, parses access flags, and checks DCOM for presence of potentially dangerous methods (i.e. Shell,Exec,DDEInitiate). In the default mode it just dumps all permissions, one per line. When "-audit" flag is added the script will also enumerate all methods exposed by given DCOM and check them against blacklist.

### Help

```
-=[ DCOM-Audit v0.1 ]=-
        by op7ic

Usage: powershell .\DCOM-Audior.ps1 [options]

Options:
  -audit    Audit all listed DCOM for potentially dangerous methods  
```

### Output

![Alt text](pic/dcom-run.png?raw=true "Standard Output")

### Interpreting Output

| Permission  | Explanation | 
| ------------- | ------------- |
| Access Permission | Describes the Access Control List (ACL) of the principals that can access instances of this class. This ACL is used only by applications that do not call CoInitializeSecurity. Can be modified as per https://docs.microsoft.com/en-gb/windows/desktop/com/defaultaccesspermission|
| Launch Permission | Describes the Access Control List (ACL) of the principals that can start new servers for this class. Can be modified as per https://docs.microsoft.com/en-gb/windows/desktop/com/defaultlaunchpermission |
| Default Permission | As per https://docs.microsoft.com/en-gb/windows/desktop/com/com-security-defaults |
| Local Launch | This value represents the right of a security principal to use ORB-specific local mechanisms to cause a component to be executed, where the precise meaning of execute depends on the context |  
| Local Activate | This value represents the right of a security principal to use ORB-specific local mechanisms to activate a component |
| Remote Launch | This value represents the right of a security principal to use ORB-specific remote mechanisms to cause a component to be executed, where the precise meaning of execute depends on the context |
| Remote Activation | This value represents the right of a security principal to use ORB-specific remote mechanisms to activate a component |

Sources: 

https://docs.microsoft.com/en-gb/windows/desktop/com/appid-key

https://docs.microsoft.com/en-us/windows/desktop/com/access-control-lists-for-com

https://msdn.microsoft.com/en-us/library/dd366181.aspx

https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ns-accctrl-_actrl_access_entrya

https://github.com/Microsoft/Windows-classic-samples/blob/master/Samples/Win7Samples/com/fundamentals/dcom/dcomperm/ListAcl.Cpp

### TL;DR
This script basically dumps & lists the following settings from "dcomcnfg.exe":

![Alt text](pic/what-it-audits.png?raw=true "What It Audits")

### Why this is important? 

COM server applications have two types of permissions: launch permissions and access permissions. Launch permissions control authorization to start a COM server during COM activation if the server is not already running. These permissions are defined as security descriptors that are specified in registry settings. Access permissions control authorization to call a running COM server. These permissions are defined as security descriptors provided to the COM infrastructure through the CoInitializeSecurity API, or using registry settings. Both launch and access permissions allow or deny access based on principals, and make no distinction as to whether the caller is local to the server or remote.

The two distances that are defined are Local and Remote. A Local COM message arrives by way of the Local Remote Procedure Call (LRPC) protocol, while a Remote COM message arrives by way of a remote procedure call (RPC) host protocol like transmission control protocol (TCP).

COM activation is the act of getting a COM interface proxy on a client by calling CoCreateInstance or one of its variants. As a side effect of this activation process, sometimes a COM server must be started to fulfill the client's request. A launch permissions ACL asserts who is allowed to start a COM server. An access permissions ACL asserts who is allowed to activate a COM object or call that object once the COM server is already running.

Call and activation rights are separated to reflect to two distinct operations and to move the activation right from the access permission ACL to the launch permission ACL. Because activation and launching are both related to acquiring an interface pointer, activation and launch access rights logically belong together in one ACL. And because you always specify launch permissions through configuration (as compared to access permissions, which are often specified programmatically), putting the activation rights in the launch permission ACL provides the administrator with control over activation.

Source: 

https://docs.microsoft.com/en-us/windows/desktop/com/dcom-security-enhancements-in-windows-xp-service-pack-2-and-windows-server-2003-service-pack-1

### Tested On

* Windows 7 x86
* Windows 7 x64
* Windows 10 x64

### Limitations

* The script is quite slow
* In order to check for exposed methods this script will initialize given CLSID via "[activator]::CreateInstance([type]::GetTypeFromCLSID())" and then release initialized object via "[System.Runtime.Interopservices.Marshal]::ReleaseComObject()". This might cause existing DCOM objects to shut down.


## TODO
- [ ] Output to files 
- [ ] Audit option need work. DCOM object errors are currently suppressed but that is not correct approach.

