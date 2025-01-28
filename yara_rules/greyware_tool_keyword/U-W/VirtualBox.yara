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
        $string2 = /\ssharedfolder\sadd\s.{0,1000}\s\-hostpath\sc\:\\\s\-automount/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string3 = /\\VboxHeadless\.exe\\"\s\-startvm\s.{0,1000}\s\-v\soff/ nocase ascii wide
        // Description: adding the entire C drive as a shared folder for a VM
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string4 = /\<SharedFolder\sname\=\\".{0,1000}\\"\shostPath\=\\"C\:\\\\"\swritable\=\\"true\\"\/\>/ nocase ascii wide
        // Description: hiding VirtualBox notifications - abused by attacker to hide their VM persistence
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string5 = "setextradata global GUI/SuppressMessages \"all\"" nocase ascii wide
        // Description: hiding VirtualBox notifications - abused by attacker to hide their VM persistence
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string6 = "setextradata global GUI/SuppressMessages all" nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string7 = /start\s\/min\s\\"C\:\\Program\sFiles\\Oracle\\VirtualBox\\VBoxManage\.exe\\"\sstartvm\s.{0,1000}\s\-type\sheadless/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string8 = /VboxHeadless\.exe\s\-startvm\s.{0,1000}\s\-v\soff/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string9 = /VBoxManage\sstartvm\s.{0,1000}\s\-\-type\sheadless/ nocase ascii wide
        // Description: hiding VirtualBox notifications - abused by attacker to hide their VM persistence
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string10 = /VBoxManage.{0,1000}setextradata\sglobal\sGUI\/SuppressMessages\s/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string11 = /VBoxManage\.exe\sstartvm\s.{0,1000}\s\-\-type\sheadless/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string12 = /VBoxManage\.exe\sstartvm\s.{0,1000}\s\-v\soff/ nocase ascii wide
        // Description: Starts VirtualBox in headless mode
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string13 = /VBoxManage\.exe\\"\sstartvm\s.{0,1000}\s\-\-type\sheadless/ nocase ascii wide

    condition:
        any of them
}
