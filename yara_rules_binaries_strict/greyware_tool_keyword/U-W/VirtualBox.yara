rule VirtualBox
{
    meta:
        description = "Detection patterns for the tool 'VirtualBox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VirtualBox"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: adding the entire C drive as a shared folder for a VM
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string1 = /\shostPath\=\\"c\:\\\\"\swritable\=\\"true\\"\sautoMount\=\\"true\\"/ nocase ascii wide
        // Description: adding the entire C drive as a shared folder for a VM
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string2 = /\ssharedfolder\sadd\s.{0,100}\s\-hostpath\sc\:\\\s\-automount/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string3 = /\\VboxHeadless\.exe\\"\s\-startvm\s.{0,100}\s\-v\soff/ nocase ascii wide
        // Description: adding the entire C drive as a shared folder for a VM
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string4 = /\<SharedFolder\sname\=\\".{0,100}\\"\shostPath\=\\"C\:\\\\"\swritable\=\\"true\\"\/\>/ nocase ascii wide
        // Description: hiding VirtualBox notifications - abused by attacker to hide their VM persistence
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string5 = "setextradata global GUI/SuppressMessages \"all\"" nocase ascii wide
        // Description: hiding VirtualBox notifications - abused by attacker to hide their VM persistence
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string6 = "setextradata global GUI/SuppressMessages all" nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string7 = /start\s\/min\s\\"C\:\\Program\sFiles\\Oracle\\VirtualBox\\VBoxManage\.exe\\"\sstartvm\s.{0,100}\s\-type\sheadless/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string8 = /VboxHeadless\.exe\s\-startvm\s.{0,100}\s\-v\soff/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string9 = /VBoxManage\sstartvm\s.{0,100}\s\-\-type\sheadless/ nocase ascii wide
        // Description: hiding VirtualBox notifications - abused by attacker to hide their VM persistence
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string10 = /VBoxManage.{0,100}setextradata\sglobal\sGUI\/SuppressMessages\s/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string11 = /VBoxManage\.exe\sstartvm\s.{0,100}\s\-\-type\sheadless/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string12 = /VBoxManage\.exe\sstartvm\s.{0,100}\s\-v\soff/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string13 = /VBoxManage\.exe\\"\sstartvm\s.{0,100}\s\-\-type\sheadless/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
