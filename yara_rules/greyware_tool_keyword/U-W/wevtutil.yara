rule wevtutil
{
    meta:
        description = "Detection patterns for the tool 'wevtutil' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wevtutil"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string1 = /cmd.{0,1000}\swevtutil\.exe\scl\s/ nocase ascii wide
        // Description: loops through event logs using wevtutil.exe to prepare to clear them
        // Reference: https://github.com/CCob/Shwmae
        $string2 = /for\s\/F\s\\"tokens\=.{0,1000}\\"\s\%\%G\sin\s\(\'wevtutil\.exe\sel\'\)\sDO\s\(call\s\:do_clear\s\\"\%\%G\\"\)/ nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string3 = "wevtutil cl " nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string4 = "wevtutil clear-log" nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string5 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-ATAPort\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string6 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-ClassPnP\/A/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string7 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Disk\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string8 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageManagement\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string9 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-Driver\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string10 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-ManagementAgent\/WHC/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string11 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-SpaceManager\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string12 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Storport\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string13 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Tiering\/Admin/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string14 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Tiering\-IoHeat\/Heat/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string15 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Store\/Operational/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string16 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Subsys\-Csr\/Operational/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string17 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Subsys\-SMSS\/Operational/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string18 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Superfetch\/Main/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string19 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Superfetch\/PfApLog/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string20 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Superfetch\/StoreLog/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string21 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Sysmon\/Operational/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string22 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Sysprep\/Analytic/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string23 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-System\-Profile\-HardwareId\/Diagnostic/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string24 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-SystemSettingsHandlers\/Debug/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string25 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-SystemSettingsThreshold\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string26 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TaskbarCPL\/Diagnostic/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string27 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TaskScheduler\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string28 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TCPIP\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string29 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TerminalServices\-/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string30 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Tethering\-Manager\/Analytic/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string31 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Tethering\-Station\/Analytic/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string32 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-ThemeCPL\/Diagnostic/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string33 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-ThemeUI\/Diagnostic/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string34 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Threat\-Intelligence\/Analytic/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string35 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Time\-Service\/Operational/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string36 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TSF\-msctf\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string37 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TTS\/Diagnostic/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string38 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TunnelDriver/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string39 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TWinUI\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string40 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TZSync\// nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string41 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TZUtil\/Operational/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string42 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UAC\/Operational/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string43 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UAC\-FileVirtualization\/Operational/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string44 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UIAnimation\/Diagnostic/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string45 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UI\-Shell\/Diagnostic/ nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string46 = /wevtutil\.exe\scl\s/ nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string47 = /wevtutil\.exe\sclear\-log/ nocase ascii wide
        // Description: disable a specific eventlog
        // Reference: N/A
        $string48 = /wevtutil\.exe\ssl\s.{0,1000}\s\/e\:false/ nocase ascii wide

    condition:
        any of them
}
