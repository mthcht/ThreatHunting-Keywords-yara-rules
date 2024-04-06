rule Amnesiac
{
    meta:
        description = "Detection patterns for the tool 'Amnesiac' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amnesiac"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string1 = /\sAsk4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string2 = /\sDpapi\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string3 = /\sdumper\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string4 = /\sLocalAdminAccess\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string5 = /\$CertutilDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string6 = /\/Amnesiac\.git/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string7 = /\/Ask4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string8 = /\/Dpapi\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string9 = /\/dumper\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string10 = /\/Ferrari\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string11 = /\/File\-Server\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string12 = /\/HiveDump\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string13 = /\/NETAMSI\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string14 = /\/TakeMyRDP2\.0/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string15 = /\[\+\]\sAsk4Creds\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string16 = /\[\+\]\sCreating\sService\son\sRemote\sTarget\?/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string17 = /\[\+\]\sDomain\sPassword\sSpray\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string18 = /\[\+\]\sDpapiDump\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string19 = /\[\+\]\sHiveDump\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string20 = /\[\+\]\sKeylogger\sstarted\swith\sPID\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string21 = /\[\+\]\sPayload\sformat\:\spwsh/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string22 = /\[\+\]\sPInject\sLoaded\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string23 = /\[\+\]\sPowershellKerberos\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string24 = /\[\+\]\sPowerView\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string25 = /\[\+\]\sRDP\sKeylog\ssaved\sto\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string26 = /\[\+\]\sRDP\sKeylogger\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string27 = /\[\+\]\sRDP\sKeylogger\sstarted\swith\sPID\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string28 = /\[\+\]\sRubeus\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string29 = /\[\+\]\sSMBRemoting\sand\sWMIRemoting\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string30 = /\[\+\]\sToken\-Impersonation\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string31 = /\\Ask4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string32 = /\\Dpapi\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string33 = /\\dumper\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string34 = /\\Ferrari\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string35 = /\\File\-Server\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string36 = /\\HiveDump\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string37 = /\\LocalAdminAccess\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string38 = /\\NETAMSI\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string39 = /\\PInject\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string40 = /3xpl01tc0d3r\/ProcessInjection/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string41 = /678ce24e\-70c4\-47b1\-b595\-ca0835ba35d9/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string42 = /Access_Check\s\-Method\sPSRemoting/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string43 = /Amnesiac\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string44 = /Amnesiac\-main\.zip/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string45 = /c\:\\Users\\Public\\Documents\\log\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string46 = /Find\-LocalAdminAccess\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string47 = /Find\-LocalAdminAccess\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string48 = /GhostPack\/Rubeus/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string49 = /Invoke\-DCSync/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string50 = /Invoke\-GrabTheHash/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string51 = /Invoke\-HiveDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string52 = /Invoke\-Kirby/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string53 = /Invoke\-LSADump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string54 = /Invoke\-PassSpray/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string55 = /Invoke\-Patamenia\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string56 = /Invoke\-SAMDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string57 = /Invoke\-SessionHunter/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string58 = /Invoke\-SMBRemoting/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string59 = /Invoke\-WMIRemoting/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string60 = /Leo4j\/Amnesiac/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string61 = /MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string62 = /msfvenom\s\-p\swindows\/x64\/exec/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string63 = /MzHmO\/PowershellKerberos/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string64 = /PassSpray\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string65 = /powershell\.exe\s\-enc\s\$B64ServerScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string66 = /RDPKeylog\.exe/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string67 = /Rubeus\screatenetonly\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string68 = /shell_smbadmin\s\-Targets\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string69 = /shell_tknadmin\s\-Domain\s.{0,1000}\s\-DomainController\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string70 = /shell_wmiadmin\s\-Domain\s.{0,1000}\s\-DomainController/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string71 = /ShellGen\spowershell\.exe\s\-ep\sbypass\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string72 = /Spray\san\sempty\spassword\sacross\sthe\sDomain/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string73 = /TGT_Monitor\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string74 = /Tkn_Access_Check\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string75 = /tmenochet\/PowerDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string76 = /Token\-Impersonation\s\-Rev2Self/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string77 = /Token\-Impersonation\s\-Steal/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string78 = /Token\-Impersonation\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string79 = /vletoux\/MakeMeEnterpriseAdmin/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string80 = /\-WindowS\sHidden\s\-ep\sBypass\s\-enc\s\$b64FileServerMonitoringScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string81 = /\-WindowS\sHidden\s\-ep\sBypass\s\-enc\s\$b64monitoringScript/ nocase ascii wide

    condition:
        any of them
}
