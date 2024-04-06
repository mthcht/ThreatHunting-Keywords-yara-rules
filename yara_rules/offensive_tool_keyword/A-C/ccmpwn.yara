rule ccmpwn
{
    meta:
        description = "Detection patterns for the tool 'ccmpwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ccmpwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string1 = /\sccmpwn\.py/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string2 = /\sexec\s\-dll\s.{0,1000}\.dll\s\-config\s.{0,1000}\.config/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string3 = /\.py\s.{0,1000}\scoerce\s\-computer\s/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string4 = /\/ccmpwn\.git/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string5 = /\/ccmpwn\.py/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string6 = /\\ccmpwn\.py/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string7 = /\\ccmpwn\\/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string8 = /\\http_SCNotification\.exe/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string9 = /\\smb_SCNotification\.exe/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string10 = /5c611fb030683dba08662997836b3b308c0278130bf2eee6ac6af6a4332285fe/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string11 = /CcmExec\smight\snot\sbe\sinstalled\son\starget/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string12 = /CcmExec\sservice\snot\saccessible\son\sremote\ssystem\!\s\:\(/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string13 = /Downloading\soriginal\sSCNotification\.exe\.config\svia\sSMB/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string14 = /impacket\.dcerpc/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string15 = /mandiant\/ccmpwn/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string16 = /SCNotification\.exe\.config\.malicious/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string17 = /smbclient\.getFile\(\'C\$\'\,\s\'Windows\/CCM\/SCNotification\.exe\.config/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string18 = /Starting\sCcmExec\sservice\.\sWait\saround\s30\sseconds\sfor\sSCNotification\.exe\sto\srun\sconfig\sfile/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string19 = /templates\/http_SCNotification\.exe/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string20 = /templates\/smb_SCNotification\.exe/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string21 = /Uploading\smalicious\sDLL\svia\sSMB/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string22 = /Uploading\smalicious\sSCNotification\.exe\.config\svia\sSMB/ nocase ascii wide

    condition:
        any of them
}
