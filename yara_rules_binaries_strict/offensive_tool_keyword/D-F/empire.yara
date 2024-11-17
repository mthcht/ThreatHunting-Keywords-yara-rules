rule empire
{
    meta:
        description = "Detection patterns for the tool 'empire' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "empire"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string1 = /\s\$FodHelperPath/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string2 = /\s\-AgentDelay\s/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string3 = /\s\-AgentJitter\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string4 = /\s\-bootkey\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string5 = /\s\-ChildPath\s.{0,100}fodhelper\.exe/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string6 = /\s\-ChildPath\s.{0,100}sdclt\.exe/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string7 = /\s\-CollectionMethod\sstealth/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string8 = /\s\-ComputerName\s\-ServiceEXE\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string9 = /\s\-ConType\sbind\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string10 = /\s\-ConType\sreverse\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string11 = /\s\-CShardDLLBytes/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string12 = /\s\-DllName\s.{0,100}\s\-FunctionName\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string13 = /\s\-Domain\s.{0,100}\s\-SMB1\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string14 = /\s\-DoNotPersistImmediately\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string15 = /\s\-DumpCerts\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string16 = /\s\-DumpCreds\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string17 = /\s\-DumpForest\s\-Users\s.{0,100}krbtgt/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string18 = /\s\-ElevatedPersistenceOption\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string19 = /\sempire\.arguments/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string20 = /\sempire\.client\./ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string21 = /\sempire\.py/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string22 = /\s\-Enumerate\s.{0,100}\s\-Module\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string23 = /\s\-ExeArguments\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string24 = /\s\-FullPrivs\s.{0,100}\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string25 = /\s\-GHUser\s.{0,100}\s\-GHRepo\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string26 = /\s\-Hosts\s.{0,100}\s\-TopPorts\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string27 = /\shttp_malleable/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string28 = /\s\-ImpersonateUser\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string29 = /\s\-ImportDllPathPtr\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string30 = /\sInveigh\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string31 = /\s\-JMXConsole\s\-AppName\s/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string32 = /\s\-KillDate\s/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string33 = /\s\-KillDays\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string34 = /\s\-LLMNRTTL\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string35 = /\s\-LNKPath\s.{0,100}\s\-EncScript\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string36 = /\s\-mDNSTTL\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string37 = /\s\-NBNSTTL\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string38 = /\snet\slocalgroup\sadministrators\sTater\s\/add/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string39 = /\s\-NoBase64\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string40 = /\s\-NoP\s\-sta\s\-NonI\s\-W\sHidden\s\-Enc\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string41 = /\s\-p\s1337\:1337\s\-p\s5000\:5000/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string42 = /\s\-PasswordList\s/ nocase ascii wide
        // Description: Empire scripts arguments. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string43 = /\s\-payload\s.{0,100}\-Lhost\s.{0,100}\-Lport/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string44 = /\s\-PayloadPath\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string45 = /\s\-PEPath\s.{0,100}\s\-ExeArgs\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string46 = /\s\-PermanentWMI\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string47 = /\s\-PersistenceScriptName\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string48 = /\s\-PersistentScriptFilePath\s/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string49 = /\s\-\-port\s1337/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string50 = /\s\-PWDumpFormat\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string51 = /\s\-Registry\s\-AtStartup\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string52 = /\s\-RemoteDllHandle\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string53 = /\s\-RevToSelf\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string54 = /\s\-Rhost\s.{0,100}\s\-WARFile\shttp/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string55 = /\s\-Rhosts\s.{0,100}\s\-Password\s.{0,100}\s\-Directory\s.{0,100}\s\-Dictionary\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string56 = /\s\-Rhosts\s.{0,100}\s\-Path\s.{0,100}\.txt\s\-Port\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string57 = /\s\-ScheduledTask\s\-OnIdle\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string58 = /\s\-ServiceName\s.{0,100}\s\-PipeName\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string59 = /\sSet\-MasterBootRecord/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string60 = /\s\-SiteListFilePath\s.{0,100}\s\-B64Pass\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string61 = /\sSnifferSpoofer/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string62 = /\s\-SpooferIP\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string63 = /\s\-Target\s.{0,100}\s\-AllDomain\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string64 = /\s\-Target\s.{0,100}\s\-InitialGrooms\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string65 = /\s\-Target\s.{0,100}\s\-Shellcode\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string66 = /\s\-type\suser\s\-search\s.{0,100}\s\-DomainController\s.{0,100}\s\-Credential\s.{0,100}\s\-list\syes/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string67 = /\s\-UserList\s.{0,100}\s\-Domain\s.{0,100}\s\-PasswordList\s.{0,100}\s\-OutFile\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string68 = /\s\-Username\s.{0,100}\s\-Hash\s.{0,100}\s\-Command\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string69 = /\s\-UserPersistenceOption\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string70 = /\s\-VaultElementPtr\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string71 = /\swindows\/csharp_exe/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string72 = /\s\-WorkingHours\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string73 = /\sYour\spayload\shas\sbeen\sdelivered/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string74 = /\$PipeName\s\=\s\\"TestSVC\\"/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string75 = /\$Taskname\=\\"Tater\\"/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string76 = /\/\/localhost\:1337/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string77 = /\/api\/admin\/shutdown\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string78 = /\/api\/agents\/.{0,100}\/kill\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string79 = /\/api\/agents\/all\/kill\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string80 = /\/api\/agents\/all\/shell\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string81 = /\/api\/agents\/CXPLDTZCKFNT3SLT\/shell\?/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string82 = /\/api\/agents\/stale\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string83 = /\/api\/agents\/XMY2H2ZPFWNPGEAP\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string84 = /\/api\/listeners\/all\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string85 = /\/api\/modules\/collection\/.{0,100}\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string86 = /\/api\/modules\/credentials.{0,100}\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string87 = /\/api\/reporting\/agent\/initial\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string88 = /\/api\/reporting\/msg\/.{0,100}\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string89 = /\/api\/reporting\/type\/checkin\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string90 = /\/api\/stagers\/dll\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string91 = /\/api\/stagers\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string92 = /\/api\/users\/1\/disable\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string93 = /\/api\/v2\/starkiller/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string94 = /\/client\/generated\-stagers\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string95 = /\/data\/empire\.db/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string96 = /\/data\/empire\.orig\.key/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string97 = /\/download\-stager\.js/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string98 = /\/ducky\.py/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string99 = /\/Empire\.git/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string100 = /\/empire\/client\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string101 = /\/empire\:latest/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string102 = /\/empire\-chain\.pem/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string103 = /\/EmpireProject/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string104 = /\/evilhost\:/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string105 = /\/Get\-LsaSecret\./ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string106 = /\/hop\.php/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string107 = /\/HTTP\-Login\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string108 = /\/Invoke\-RunAs\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string109 = /\/lateral_movement\// nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string110 = /\/lateral_movement\/.{0,100}\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string111 = /\/logs\/empire_server\.log/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string112 = /\/MailRaider\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string113 = /\/network\/bloodhound3/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string114 = /\/persistence\/.{0,100}\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string115 = /\/persistence\/.{0,100}\.psm1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string116 = /\/privesc\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string117 = /\/ps\-empire/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string118 = /\/ReferenceSourceLibraries\/Sharpire/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string119 = /\/server\/common\/stagers\.py/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string120 = /\/Sharpire\.exe/ nocase ascii wide
        // Description: Empire executable paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string121 = /\/situational_awareness\/.{0,100}\.exe/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string122 = /\/situational_awareness\/.{0,100}\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string123 = /\/smb\/psexec\.rb/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string124 = /\/sprayed\-creds\.txt/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string125 = /\/stagers\/.{0,100}\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string126 = /\/stagers\/CSharpPS/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string127 = /\/tmp\/empire/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string128 = /\/tools\/psexec\.rb/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string129 = /\/trollsploit\// nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string130 = /\/x64_slim\.dll/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string131 = /\/xar\-1\.5\.2\.tar\.gz/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string132 = /\\EmpireCompiler\.dll/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string133 = /\\hijackers\\/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string134 = /\\PSRansom\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string135 = /\\Sharpire\.exe/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string136 = /\\sprayed\-creds\.txt/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string137 = /\\Temp\\blah\.exe/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string138 = /\\UACBypassTest\.txt/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string139 = /0207936279f3e40608ea72aae76312c3e5485f6eabd041d5c690f485c523a795/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string140 = /0c79bc58224e71882e48b6230f3a90ec516f30ba8a6a431f7d2f6323de581a81/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string141 = /0fa7194f72ad2e12774792f48c2cc01e4828356087210370acdd9c66b67f818b/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string142 = /10226b3b8594c981077a5e415bd98787c94b6f3f2ca48a50089fdf3f2c2547e8/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string143 = /1085654ad66ba105edeca8e068047afdcec8f3d35aaa2dc09cf5cb5518971e15/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string144 = /12da3e3bfe44e83838a66ed2c8cbaf3fd7153b815d21dd14c2f8de2f10130b3d/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string145 = /1337.{0,100}\/api\/agents\/.{0,100}\/results\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string146 = /1337.{0,100}\/api\/creds\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string147 = /1337.{0,100}\/api\/listeners\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string148 = /15065a09f2a944aa4376a3efe035b209f2c9617be19e08640320fb874e0e991c/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string149 = /1ee8a433f650466547e5003bcf470eb70cfcaee27cbebae2f55adbcbacd6bf40/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string150 = /21f37987d11f82d9a0b38b6caca5b5c7967172f3204c8ecc98cb3a5033097467/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string151 = /242edf5f22175e7bb921568de525cd1469c3462fbb5943a04f2cc681cff764f4/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string152 = /24b6f5f69fbc819dcfbdaa0efcfbf5a71f26f651e5c2310ebe495b193f89cce9/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string153 = /25110aab44570c065061044d38afc50eea45ca5f78bb2b70b0941d63c979cf62/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string154 = /285a2bf9a6a6a90d942d0c20832f5c0722e3aa557498cd1b6208b52932bbc18d/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string155 = /2873fe0d14429c67afb56a58407a9ac664b395eb0fa7c8101f69b055e3f747fa/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string156 = /2c0a644ec77673d8ec16808a8ac299733ee6e91a3fed0c8da41d6d73812b0d29/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string157 = /2e70433f8b5f60e28dbd95757dd4bf967fa744142deac4b3bcb0d3b11cb99753/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string158 = /32cd91c759b8cb4efca9582ee8ff760f1121f109a5e54a6c6da956713ef81f0f/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string159 = /3644992e6ddad57730c25549175afaded580cd12226675105f71525e7d089d24/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string160 = /382c77a7693178867a24912db26b69a1fe5d508cde83ea89309758ef5d001e44/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string161 = /41792ea386bced0624ba2066ed3616167eebb93212f6751e60382c0ba10a9e59/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string162 = /4ed4145e2a1ea00c2cf463f86d627341b58d0e0887ae317ebfce6dd5d48f8749/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string163 = /573b83b3dc86832085eca5958fa11c0b5874edb3fdf84a016a21a8cc40454ea2/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string164 = /59d6b8ce447b8168f7d17f18a1584dd54c543fed2b35a5b76c49c034e20dffe2/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string165 = /5aef3aec6cf7fd4f2a1b1f82768092cf7c861f3f4efb8d7b1764c51f4620e946/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string166 = /618af083df8944b89618a4bed2d4be44f901f3b9659f066d6e210ec0cb92e603/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string167 = /6be97bfbc4bdb40ea061c20d75d0c812de61b262c96f891a438fdd280aad4c6f/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string168 = /6ecb62923d16588654c77ad581388eb27873b09c2ff642cd8303c8a2d577fe53/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string169 = /722e522f4029a9e0eb3ce298d28949e304b797d242cd4ae8f81e0530ca0acc8f/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string170 = /77db549ca1d8238056074d8abda0c1715bb69f1c0b85795f1680c20960e6a757/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string171 = /798ccfbf2e5c14077023d9236363c6e6ebf3bc6b28b551c01b00e272863bdcc7/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string172 = /7e4fc58a02442bd5021c2a0b1bc032a1b65dfa1dbb182fc9a13e4716da7c51d9/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string173 = /7e5d70e9ea31688ed3b6192e0f4bc7ba02b6d3fc772598ac187c02275a44cc02/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string174 = /7fdf7529eb3c25f47136fa12a74040e38f4eda6cdd66f760977e537a292abea6/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string175 = /841f439c8f42ffe1fa88303a9d7fd8268b6cdf9dd8b91704ba2dd8a7b8f813a3/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string176 = /86943e3a790e194a2f76aa2c4ed2832e19fe4e7a45eeebe5f5bc62fd16825bd5/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string177 = /8da1165d0f8bc514c82d5818ac89bb7a5e31d1f78258ac8beecb7b73fc5d857a/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string178 = /91a40fb5af592e1b63099fb236a1c955b47c4699197651b9ae1507ecbf4ad2ea/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string179 = /95df94b5f2e9428ee39f9f6706fd746a116a8afe9eeb3b318c576bbb934e35a4/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string180 = /96023f92abefc6b2196bda989320836075a1fa402106fd7cc8fb546bc09502b7/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string181 = /9fb43934f7fab913cd91847ca228bba739f98f58074bcedd50a912a71b313c5c/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string182 = /a4a394d85597168c85a244e6ec4d8ff7c8a92f3938bf40dac9ba5a0ce9803d05/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string183 = /a58fa5635efa5a680c1861aca8a2e630b4031dadb901fe36df5e1f7018948275/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string184 = /ACBypassTest/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string185 = /Add\-Persistence/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string186 = /Add\-PSFirewallRules/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string187 = /apt\sinstall\spowershell\-empire/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string188 = /bc2ef0da409c8c1a026e13d11b4cf32995e4a7e742c097ca9d1594aba8d3d4e3/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string189 = /bc\-security\/empire/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string190 = /bcsecurity\/empire\:latest/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string191 = /BC\-SECURITY\/Starkiller/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string192 = /Bitmap\-Elevate/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string193 = /BloodHound\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string194 = /BloodHound3\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string195 = /Building\sSYSTEM\simpersonation/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string196 = /BypassUACTokenManipulation/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string197 = /c12cad06d0e93742fd0ce0c698c654ff3c86b567dcc4102cd2c5d931d77dcc64/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string198 = /c5b69369f46c94d6c1ac5c2f3808be48fa6d790c7d7d909d82850cc8774a14ac/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string199 = /c85c649826d3f0cb619861663dbc70669e6705eec03ddb383fc9ef92125aaf25/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string200 = /c93ff0ad29732505e9679eed6561ceef907bcb1f5df9b6a588c23e484df85681/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string201 = /cc3f112ed5af9b0b4de3ab165c1a08b0d3d24323f8492f0513a0af9e06e95eff/ nocase ascii wide
        // Description: Empire dll paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string202 = /code_execution\/.{0,100}\.dll/ nocase ascii wide
        // Description: Empire executable paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string203 = /code_execution\/.{0,100}\.exe/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string204 = /code_execution\/.{0,100}\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string205 = /ConvertFrom\-LDAPLogonHours/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string206 = /ConvertTo\-LogonHoursArray/ nocase ascii wide
        // Description: empire function name. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string207 = /ConvertTo\-Rc4ByteStream/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string208 = /Create\-NamedPipe/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string209 = /Create\-SuspendedWinLogon/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string210 = /Create\-WinLogonProcess/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string211 = /csharp_inject_bof_inject/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string212 = /D5865774\-CD82\-4CCE\-A3F1\-7F2C4639301B/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string213 = /d78fa8da51c45a84c22819f0ab4f2b77135c9e8b48f693dde65384ecc3b8636c/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string214 = /d7e3d2ef31bf5905d593420dbd3aa92e709d2524fa63ffa0bb3b75dc2ddc408f/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string215 = /Decode\-RoutingPacket/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string216 = /DecryptNextCharacterWinSCP/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string217 = /DecryptWinSCPPassword/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string218 = /dedc1f4578fd081f28e2cca23dcb518fad39f9f782755bfa33e9723f32bb4487/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string219 = /Discover\-PSMSExchangeServers/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string220 = /Discover\-PSMSSQLServers/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string221 = /\-DllInjection\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string222 = /\-DllName\s.{0,100}\-Module\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string223 = /Do\-AltShiftEsc/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string224 = /Do\-AltShiftTab/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string225 = /docker\srun\s\-it\s\-p\s1337\:1337\s\-p\s5000\:5000\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string226 = /\-Domain\s.{0,100}\s\-AllowDelegation\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string227 = /\-Domain\s.{0,100}\s\-SPN\s/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string228 = /download\s.{0,100}bloodhound/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string229 = /DownloadAndExtractFromRemoteRegistry/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string230 = /dumpCredStore\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string231 = /\-DumpForest\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string232 = /e17b62d1052bbed122fd65f701fe79600dc84b9dc9d4cd1e17c1dca2cc2c2e71/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string233 = /e55c296872a04e46369c46c23bae5707cd7d2e079a2f8350015475b5eecd3e17/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string234 = /e8e5705168a9c66d1a4cf17d3ef2928b9141bffa3ca28a0482536e7900975a87/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string235 = /echo\s.{0,100}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string236 = /ee58b36f91a49518422e7eab0fd0c82c9a154f95ae9dde863a02bc4da7ff398c/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string237 = /egresscheck\-framework/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string238 = /ElevatePrivs/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string239 = /Empire\sFramework\sGUI/ nocase ascii wide
        // Description: empire command lines patterns
        // Reference: https://github.com/EmpireProject/Empire
        $string240 = /empire\s\-\-rest\s/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string241 = /empire\s\-\-server\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string242 = /empire\.server\.api\.v2/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string243 = /empire\/client\/.{0,100}\.py/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string244 = /empire\/server\/.{0,100}\.py/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string245 = /empire\/server\/downloads\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string246 = /empire\/server\/downloads\/logs\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string247 = /empire\/server\/downloads\/logs\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string248 = /Empire\@bc\-security\.org/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string249 = /empire_server\./ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string250 = /empireadmin/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string251 = /empire\-chain\.pem/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string252 = /EmpireCORSMiddleware/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string253 = /Empire\-GUI\.git/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string254 = /Empire\-master/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string255 = /empire\-priv\.key/ nocase ascii wide
        // Description: Empire is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent. and a pure Python 2.6/2.7 Linux/OS X agent. It is the merge of the previous PowerShell Empire and Python EmPyre projects. The framework offers cryptologically-secure communications and a flexible architecture. On the PowerShell side. Empire implements the ability to run PowerShell agents without needing powershell.exe. rapidly deployable post-exploitation modules ranging from key loggers to Mimikatz. and adaptable communications to evade network detection. all wrapped up in a usability-focused framework. PowerShell Empire premiered at BSidesLV in 2015 and Python EmPyre premeiered at HackMiami 2016.
        // Reference: https://github.com/EmpireProject/Empire
        $string256 = /EmpireProject/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string257 = /Empire\-Sponsors\.git/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string258 = /empire\-test\-kalirolling/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string259 = /Enable\-SeAssignPrimaryTokenPrivilege/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string260 = /Enable\-SeDebugPrivilege/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string261 = /Encrypt\-Bytes/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string262 = /Enum\-AllTokens/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string263 = /Enum\-Creds/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string264 = /EternalBlue\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string265 = /\-EventVwrBypass/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string266 = /ExfilDataToGitHub/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string267 = /Exploit\-EternalBlue\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string268 = /Exploit\-JBoss\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string269 = /Exploit\-JBoss\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string270 = /Exploit\-Jenkins/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string271 = /Exploit\-Jenkins\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string272 = /Exploit\-JMXConsole/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string273 = /Export\-PowerViewCSV/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string274 = /f04b79d7179c98ce705876849a20f67bcff5c977f4f7865226e26296f1e80966/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string275 = /f3e392c770e87e69c6af2d3e83bd4b6190e6e09ce4aa4a681316dbb11582e1b3/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string276 = /f7e5471eda155f8ff46a63d00cab80b18a7eb62cbd1865d30bcff1b074af1887/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string277 = /fbd9f058f3838363b1f6f3e63b22ae60532af2f21f5c73b18899c9b0b888e3f3/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string278 = /febf23d1ae51d53d18aff75baa9b3c8f13775b5399e6d15ad138d1a9dcc2b871/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string279 = /Fetch\-And\-Brute\-Local\-Accounts\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string280 = /Find\-4624Logons/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string281 = /Find\-4648Logons/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string282 = /Find\-AppLockerLogs/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string283 = /Find\-DLLHijack/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string284 = /Find\-DomainShare\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string285 = /Find\-DomainShare\s\-CheckShareAccess/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string286 = /Find\-Fruit\./ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string287 = /Find\-Fruit\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string288 = /Find\-InterestingDomainAcl/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string289 = /Find\-InterestingDomainShareFile/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string290 = /Find\-KeePassconfig/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string291 = /Find\-LocalAdminAccess/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string292 = /Find\-PathDLLHijack/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string293 = /Find\-PathHijack/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string294 = /Find\-ProcessDLLHijack/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string295 = /Find\-PSScriptsInPSAppLog/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string296 = /Find\-RDPClientConnections/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string297 = /Find\-TrustedDocuments/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string298 = /Find\-TrustedDocuments\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string299 = /Find\-UserField\s\-SearchField\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string300 = /Find\-WMILocalAdminAccess/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string301 = /function\spsenum/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string302 = /generate_powershell_exe/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string303 = /generate_powershell_shellcode/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string304 = /generate_python_exe/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string305 = /generate_python_shellcode/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string306 = /generate_stageless/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string307 = /Get\-ActiveTCPConnections/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string308 = /Get\-and\-Brute\-LocalAccount\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string309 = /Get\-AppLockerConfig\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string310 = /Get\-BloodHoundData/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string311 = /Get\-BootKey/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string312 = /Get\-BrowserData\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string313 = /Get\-BrowserInformation/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string314 = /Get\-CachedGPPPassword/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string315 = /Get\-ChromeBookmarks/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string316 = /Get\-ChromeDump/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string317 = /Get\-ChromeDump/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string318 = /Get\-ChromeDump\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string319 = /Get\-ChromeHistory/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string320 = /Get\-ClipboardContents/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string321 = /Get\-ClipboardContents\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string322 = /Get\-ComputerDetails\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string323 = /GetComputersFromActiveDirectory/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string324 = /Get\-DCBadPwdCount/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string325 = /Get\-DecryptedCpassword/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string326 = /Get\-DecryptedSitelistPassword/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string327 = /Get\-DomainDFSshare/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string328 = /Get\-DomainDFSShareV1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string329 = /Get\-DomainDFSShareV2/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string330 = /Get\-DomainFileServer/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string331 = /Get\-DomainForeignUser/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string332 = /Get\-DomainGPOComputerLocalGroupMapping/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string333 = /Get\-DomainGPOUserLocalGroupMapping/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string334 = /Get\-DomainManagedSecurityGroup/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string335 = /Get\-DomainObjectACL\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string336 = /Get\-DomainSearcher/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string337 = /Get\-DomainSpn/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string338 = /Get\-DomainSPNTicket/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string339 = /Get\-FireFoxHistory/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string340 = /Get\-FoxDump\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string341 = /Get\-FoxDump/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string342 = /Get\-FoxDump\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string343 = /Get\-GPPInnerFields/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string344 = /Get\-GPPPassword/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string345 = /Get\-GPPPassword\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string346 = /Get\-ImageNtHeaders/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string347 = /Get\-IndexedItem\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string348 = /Get\-InternetExplorerBookmarks/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string349 = /Get\-InternetExplorerHistory/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string350 = /Get\-KeePassconfig/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string351 = /Get\-KeePassDatabaseKey/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string352 = /Get\-KeePassINIFields/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string353 = /Get\-KeePassXMLFields/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string354 = /Get\-KerberosServiceTicket/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string355 = /Get\-KerberosServiceTicket\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string356 = /Get\-Keystrokes/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string357 = /Get\-Keystrokes\.ps1/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string358 = /Get\-Killdate/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string359 = /Get\-LAPSPasswords/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string360 = /Get\-LAPSPasswords\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string361 = /Get\-LastLoggedon\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string362 = /Get\-LoggedOnLocal\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string363 = /Get\-LsaSecret\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string364 = /Get\-ModifiableRegistryAutoRun/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string365 = /Get\-ModifiableScheduledTaskFile/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string366 = /Get\-NetComputer\s\-Unconstrainuser/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string367 = /Get\-NetFileServer/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string368 = /Get\-NetForestDomain/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string369 = /Get\-NetLoggedon\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string370 = /Get\-NetRDPSession\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string371 = /Get\-NetUser\s\-SPN/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string372 = /Get\-NetUser\s\-UACFilter\sNOT_ACCOUNTDISABLE/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string373 = /Get\-NTLMLocalPasswordHashes/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string374 = /Get\-PacketNetBIOSSessionService/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string375 = /Get\-PacketNTLMSSPAuth/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string376 = /Get\-PacketNTLMSSPNegotiate/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string377 = /Get\-PacketRPCBind/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string378 = /Get\-PacketRPCRequest/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string379 = /Get\-PacketSMB/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string380 = /Get\-PEBasicInfo/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string381 = /Get\-PSADForestInfo\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string382 = /Get\-PSADForestKRBTGTInfo\s/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string383 = /Get\-RegAlwaysInstallElevated/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string384 = /Get\-RegAutoLogon/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string385 = /Get\-RegistryAlwaysInstallElevated/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string386 = /Get\-RegistryAutoLogon/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string387 = /Get\-RickAstley/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string388 = /Get\-RickAstley\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string389 = /Get\-RubeusForgeryArgs/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string390 = /Get\-Screenshot\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string391 = /Get\-SecurityPackages\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string392 = /Get\-ServiceUnquoted/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string393 = /Get\-SharpChromium/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string394 = /Get\-SharpChromium\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string395 = /Get\-SitelistFields/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string396 = /Get\-SiteListPassword/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string397 = /Get\-SiteListPassword\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string398 = /Get\-SPN\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string399 = /Get\-SQLInstanceDomain/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string400 = /Get\-SQLInstanceDomain\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string401 = /Get\-SQLQuery\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string402 = /Get\-SQLServerLoginDefaultPw/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string403 = /Get\-SQLSysadminCheck/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string404 = /Get\-System\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string405 = /Get\-SystemDNSServer\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string406 = /Get\-SystemNamedPipe/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string407 = /Get\-TimedScreenshot\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string408 = /Get\-UniqueTokens/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string409 = /Get\-USBKeystrokes/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string410 = /Get\-UserBadPwdCount/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string411 = /Get\-VaultCredential/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string412 = /Get\-VaultCredential\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string413 = /Get\-VulnAutoRun/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string414 = /Get\-VulnSchTask/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string415 = /Get\-WinUpdates\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string416 = /Get\-WMIRegCachedRDPConnection/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string417 = /Get\-WMIRegLastLoggedOn/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string418 = /Get\-WMIRegMountedDrive/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string419 = /Get\-WorkingHours/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string420 = /H4sIAAAAAAAEAIy5BVyTbdQ4PDbYYJSju2N0h5TSndJINyKD0RKKdIOgNIiSChIiYUurgIQoiICAlAJSiojgd9/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string421 = /Honey\shash/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string422 = /http.{0,100}\/127\.0\.0\.1.{0,100}\:1337/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string423 = /http.{0,100}\/localhost.{0,100}\:1337/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string424 = /http\:\/\/127\.0\.0\.1\:8080\/invoker\/JMXInvokerServlet/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string425 = /http\:\/\/localhost\/stager\.php/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string426 = /http\:\/\/localhost\:80\/bcsjngnk/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string427 = /http_malleable\.py/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string428 = /HTTP\-Login\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string429 = /ImportDll\:\:GetAsyncKeyState/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string430 = /Import\-DllImports/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string431 = /Import\-DllInRemoteProcess/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string432 = /Import\-PhishWinLib/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string433 = /Inject\-BypassStuff\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string434 = /Inject\-BypassStuff/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string435 = /injected\sinto\sLSASS/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string436 = /Injection.{0,100}\s\-ProcName\slsass/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string437 = /Inject\-LocalShellcode/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string438 = /Inject\-NetRipper/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string439 = /Inject\-RemoteShellcode\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string440 = /Inject\-RemoteShellcode/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string441 = /install\s\spowershell\-empire/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string442 = /Install\-ServiceBinary/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string443 = /Install\-SSP\s\-Path.{0,100}\.dll/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string444 = /Install\-SSP\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string445 = /\-Inveigh\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string446 = /Inveigh\sRelay/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string447 = /inveigh_version/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string448 = /\-InveighRelay\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string449 = /invoke\sobfuscation/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string450 = /Invoke\-ARPScan/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string451 = /Invoke\-ARPScan\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string452 = /Invoke\-Assembly\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string453 = /Invoke\-BackdoorLNK/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string454 = /Invoke\-BackdoorLNK\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string455 = /Invoke\-BloodHound/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string456 = /Invoke\-Boolang\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string457 = /Invoke\-BSOD\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string458 = /Invoke\-BypassUAC\s\-Command\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string459 = /Invoke\-BypassUAC/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string460 = /Invoke\-BypassUAC\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string461 = /Invoke\-BypassUACTokenManipulation/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string462 = /Invoke\-CallbackIEX/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string463 = /Invoke\-ClearScript/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string464 = /Invoke\-ClearScript\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string465 = /Invoke\-ClipboardMonitor/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string466 = /Invoke\-CopyFile/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string467 = /Invoke\-CredentialInjection/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string468 = /Invoke\-CredentialInjection/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string469 = /Invoke\-CredentialPhisher/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string470 = /Invoke\-CredentialPhisher/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string471 = /Invoke\-CredentialPhisher\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string472 = /Invoke\-DCOM\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string473 = /Invoke\-DCSync\s/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string474 = /Invoke\-DCSync/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string475 = /Invoke\-DeadUserBackdoor/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string476 = /Invoke\-DisableMachineAcctChange/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string477 = /Invoke\-DllEncode/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string478 = /Invoke\-DllHijackingCheck/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string479 = /Invoke\-DllInjection/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string480 = /Invoke\-DllInjection\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string481 = /Invoke\-DomainPasswordSpray/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string482 = /Invoke\-DownloadFile\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string483 = /Invoke\-DownloadFile\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string484 = /Invoke\-DropboxUpload/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string485 = /Invoke\-EgressCheck/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string486 = /Invoke\-EgressCheck\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string487 = /Invoke\-Empire\s\-Servers/ nocase ascii wide
        // Description: empire function name of agent.ps1. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string488 = /Invoke\-Empire/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string489 = /Invoke\-EnumerateLocalAdmin/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string490 = /Invoke\-EnvBypass\s\-Command\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string491 = /Invoke\-EnvBypass/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string492 = /Invoke\-EnvBypass\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string493 = /Invoke\-EternalBlue/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string494 = /Invoke\-EternalBlue/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string495 = /Invoke\-EventVwrBypass/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string496 = /Invoke\-EventVwrBypass\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string497 = /Invoke\-ExecuteMSBuild/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string498 = /Invoke\-ExecuteMSBuild\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string499 = /Invoke\-ExfilDataToGitHub/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string500 = /Invoke\-FindDLLHijack/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string501 = /Invoke\-FindPathHijack/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string502 = /Invoke\-FodHelperBypass/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string503 = /Invoke\-FodHelperBypass/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string504 = /Invoke\-FodHelperBypass\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string505 = /Invoke\-HostRecon/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string506 = /Invoke\-ImpersonateUser/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string507 = /Invoke\-Inveigh/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string508 = /Invoke\-Inveigh\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string509 = /Invoke\-InveighRelay\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string510 = /Invoke\-IronPython/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string511 = /Invoke\-IronPython\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string512 = /Invoke\-IronPython3/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string513 = /Invoke\-IronPython3\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string514 = /Invoke\-KeeThief/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string515 = /Invoke\-Kerberoast/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string516 = /Invoke\-Kerberoast/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string517 = /Invoke\-LockWorkStation/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string518 = /Invoke\-MailSearch/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string519 = /Invoke\-MetasploitPayload/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string520 = /Invoke\-MetasploitPayload\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string521 = /Invoke\-Mimikatz\s\-Command\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string522 = /Invoke\-MS16032/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string523 = /Invoke\-MS16032\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string524 = /Invoke\-MS16\-032\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string525 = /Invoke\-MS16135/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string526 = /Invoke\-NetRipper/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string527 = /Invoke\-NetRipper\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string528 = /Invoke\-NinjaCopy/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string529 = /Invoke\-NinjaCopy\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string530 = /Invoke\-NTLMExtract/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string531 = /Invoke\-NTLMExtract/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string532 = /Invoke\-NTLMExtract\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string533 = /Invoke\-Ntsd\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string534 = /Invoke\-PacketCapture/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string535 = /Invoke\-PacketKnock/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string536 = /Invoke\-Paranoia/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string537 = /Invoke\-Paranoia\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string538 = /Invoke\-PatchDll/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string539 = /Invoke\-PatchDll/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string540 = /Invoke\-PhishingLNK/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string541 = /Invoke\-PhishingLNK/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string542 = /Invoke\-PhishingLNK\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string543 = /Invoke\-PortBind/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string544 = /Invoke\-PortFwd\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string545 = /Invoke\-PortFwd\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string546 = /Invoke\-Portscan/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string547 = /Invoke\-Portscan\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string548 = /Invoke\-PostExfil/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string549 = /Invoke\-PowerDump/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string550 = /Invoke\-PowerDump\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string551 = /Invoke\-PrintDemon\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string552 = /Invoke\-Printnightmare\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string553 = /Invoke\-ProcessKiller/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string554 = /Invoke\-PsExec/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string555 = /Invoke\-PsExec\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string556 = /Invoke\-PsExecCmd/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string557 = /Invoke\-PSInject/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string558 = /Invoke\-PSInject\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string559 = /Invoke\-PSRemoting/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string560 = /Invoke\-ReflectivePEInjection/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string561 = /Invoke\-ReverseDNSLookup/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string562 = /Invoke\-ReverseDNSLookup\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string563 = /Invoke\-RickASCII/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string564 = /Invoke\-RIDHijacking\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string565 = /Invoke\-SauronEye\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string566 = /Invoke\-SccmCacheFolderVulnCheck/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string567 = /Invoke\-Schtasks/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string568 = /Invoke\-SDCLTBypass/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string569 = /Invoke\-SDCLTBypass\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string570 = /Invoke\-SearchGAL/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string571 = /Invoke\-ServiceAbuse/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string572 = /Invoke\-ServiceCMD/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string573 = /Invoke\-ServiceDisable/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string574 = /Invoke\-ServiceStart/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string575 = /Invoke\-ServiceStop/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string576 = /Invoke\-ServiceUserAdd/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string577 = /Invoke\-SessionGopher/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string578 = /Invoke\-SessionGopher\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string579 = /Invoke\-SharpChiselClient/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string580 = /Invoke\-SharpChiselClient\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string581 = /Invoke\-SharpLoginPrompt\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string582 = /Invoke\-SharpSecDump\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string583 = /Invoke\-SharpSecDump\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string584 = /Invoke\-Shellcode\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string585 = /Invoke\-ShellcodeMSIL/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string586 = /Invoke\-ShellcodeMSIL\.ps1/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string587 = /Invoke\-ShellCommand/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string588 = /Invoke\-SMBAutoBrute/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string589 = /Invoke\-SMBAutoBrute/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string590 = /Invoke\-SMBAutoBrute\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string591 = /Invoke\-SMBExec\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string592 = /Invoke\-SMBLogin\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string593 = /Invoke\-SMBScanner/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string594 = /Invoke\-SmbScanner/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string595 = /Invoke\-SmbScanner\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string596 = /Invoke\-SocksProxy/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string597 = /Invoke\-SpawnAs/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string598 = /Invoke\-SpoolSample\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string599 = /Invoke\-SQLOSCMD/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string600 = /Invoke\-SQLOSCmd\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string601 = /Invoke\-Ssharp\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string602 = /Invoke\-SSharp\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string603 = /Invoke\-SSHCommand\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string604 = /Invoke\-SweetPotato/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string605 = /Invoke\-SweetPotato\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string606 = /Invoke\-Tater\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string607 = /Invoke\-Tater\./ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string608 = /Invoke\-Tater\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string609 = /Invoke\-Tater\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string610 = /Invoke\-ThreadedFunction/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string611 = /Invoke\-Thunderstruck/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string612 = /Invoke\-TokenManipulation/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string613 = /Invoke\-TokenManipulation\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string614 = /Invoke\-UserHunter/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string615 = /Invoke\-UserImpersonation/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string616 = /Invoke\-VeeamGetCreds/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string617 = /Invoke\-Vnc/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string618 = /Invoke\-Vnc\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string619 = /Invoke\-VoiceTroll\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string620 = /Invoke\-Watson/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string621 = /Invoke\-Watson\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string622 = /Invoke\-WdigestDowngrade/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string623 = /Invoke\-WindowsEnum\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string624 = /Invoke\-WinEnum/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string625 = /Invoke\-WinEnum\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string626 = /Invoke\-winPEAS\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string627 = /Invoke\-WireTap\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string628 = /Invoke\-WLMDR/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string629 = /Invoke\-WMIDebugger/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string630 = /Invoke\-WScriptBypassUAC/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string631 = /Invoke\-WScriptBypassUAC\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string632 = /Invoke\-WscriptElevate/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string633 = /Invoke\-WsusConfigCheck/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string634 = /Invoke\-ZeroLogon\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string635 = /KeePassConfig\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string636 = /\-KeePassConfigTrigger/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string637 = /KeeThief\./ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string638 = /KeeThief\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string639 = /keyword_obfuscation/ nocase ascii wide
        // Description: empire script command. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string640 = /Kicking\soff\sdownload\scradle\sin\sa\snew\sprocess/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string641 = /Killed\srunning\seventvwr/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string642 = /Killed\srunning\ssdclt/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string643 = /l33th4x0r\=cm91dGluZyBwYWNrZXQ\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string644 = /Launch\sEmpire\sCLI/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string645 = /Launch\sEmpire\sServer/ nocase ascii wide
        // Description: Empire scripts argument. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string646 = /ListMetasploitPayloads/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string647 = /LLMNRSpoofer/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string648 = /LLMNRSpoofer/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string649 = /local\:Get\-DecryptedCpassword/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string650 = /Local\:Get\-DecryptedSitelistPassword/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string651 = /Local\:Get\-DelegateType/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string652 = /Local\:Get\-KeePassXMLFields/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string653 = /Local\:Get\-PEArchitecture/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string654 = /Local\:Get\-ProcAddress/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string655 = /Local\:Invoke\-PatchDll/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string656 = /Local\:Invoke\-WscriptElevate/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string657 = /Local\:Invoke\-WscriptTrigger/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string658 = /Local\:Remove\-ADS/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string659 = /Local\:Write\-HijackDll/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string660 = /lsadump\:\:dcsync/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string661 = /make_kernel_shellcode/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string662 = /make_kernel_user_payload/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string663 = /make_smb1_anonymous_login_packet/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string664 = /make_smb1_echo_packet/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string665 = /make_smb1_free_hole_session_packet/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string666 = /make_smb1_nt_trans_packet/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string667 = /make_smb1_trans2_explo/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string668 = /make_smb2_payload_body_packet/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string669 = /make_smb2_payload_headers_packet/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string670 = /MalleableProfiles\.vue/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string671 = /mDNSSpoofer/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string672 = /MetasploitPayload\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string673 = /MiniEmpireDLL\.dll/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string674 = /NBNSBruteForceHost/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string675 = /NBNSBruteForcePause/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string676 = /NBNSBruteForceSpoofer/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string677 = /NBNSBruteForceSpoofer/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string678 = /NBNSBruteForceTarget/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string679 = /NBNSSpoofer/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string680 = /net\suser\sTater\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string681 = /New\-ElevatedPersistenceOption/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string682 = /New\-HoneyHash/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string683 = /New\-HoneyHash\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string684 = /New\-InMemoryModule\s\-ModuleName\sWin32/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string685 = /New\-InMemoryModule/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string686 = /New\-RoutingPacket/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string687 = /New\-UserPersistenceOption/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string688 = /NTLMChallengeBase64/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string689 = /NTLMExtract\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string690 = /obfuscate_command/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string691 = /obfuscated_module_source\// nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string692 = /Out\-Minidump\s/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string693 = /Out\-Minidump\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string694 = /Persistence\.psm1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string695 = /persistence\/userland\/backdoor_lnk/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string696 = /port_forward_pivot\.py/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string697 = /PowerBreach\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string698 = /powershell_code_execution_invoke_assembly/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string699 = /powershell_collection_keylogger/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string700 = /powershell_collection_screenshot/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string701 = /powershell_credentials_tokens/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string702 = /powershell_management_psinject/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string703 = /powershell_management_spawn/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string704 = /powershell_privesc_bypassuac_eventvwr/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string705 = /powershell_privesc_sherlock/ nocase ascii wide
        // Description: PowerShell offers a multitude of offensive advantages. including full .NET access. application whitelisting. direct access to the Win32 API. the ability to assemble malicious binaries in memory. and a default installation on Windows 7+. Offensive PowerShell had a watershed year in 2014. but despite the multitude of useful projects. many pentesters still struggle to integrate PowerShell into their engagements in a secure manner.
        // Reference: https://www.powershellempire.com/
        $string706 = /PowerShellEmpire/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string707 = /PowerUp\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string708 = /PowerUpSQL\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string709 = /powerview\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string710 = /ProcessFileZillaFile/ nocase ascii wide
        // Description: empire script arguments Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string711 = /\-ProcessID\s.{0,100}\s\-Dll\s.{0,100}\s\-Module\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string712 = /ProcessPPKFile/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string713 = /ProcessPuTTYLocal/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string714 = /ProcessRDPFile/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string715 = /ProcessRDPLocal/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string716 = /ProcessSuperPuTTYFile/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string717 = /Process\-TaskingPackets/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string718 = /ProcessThoroughLocal/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string719 = /ProcessThoroughRemote/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string720 = /ProcessWinSCPLocal/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string721 = /ps\-empire\sclient/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string722 = /ps\-empire\sserver/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string723 = /ps\-empire/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string724 = /\-PsExecCmd/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string725 = /\-PWDumpFormat/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string726 = /python_modules\/keyboard\.zip/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string727 = /Receive\-AgentJob/ nocase ascii wide
        // Description: Empire dll paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string728 = /ReflectivePick_x64_orig\.dll/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string729 = /ReflectivePick_x86_orig\.dll/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string730 = /ReleaseKeePass\.exe/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string731 = /Restore\-ServiceEXE\s\-ServiceName\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string732 = /\-Rhost\s.{0,100}\s\-Port\s.{0,100}\s\-Cmd\s.{0,100}cmd\s\/c/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string733 = /Running\sfinal\sexploit\spacket/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string734 = /Send\sthe\spayload\swith\sthe\sgrooms/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string735 = /server\/modules\/csharp\// nocase ascii wide
        // Description: empire command lines patterns
        // Reference: https://github.com/EmpireProject/Empire
        $string736 = /set\sCertPath\sdata\// nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string737 = /set\sCollectionMethodAll/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string738 = /Set\sListener\sdbx/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string739 = /set\sListener\sonedrive/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string740 = /set\sProfile\sapt1\.profile/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string741 = /Set\-DesktopACLToAllow/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string742 = /Set\-DesktopACLToAllowEveryone/ nocase ascii wide
        // Description: empire function name of agent.ps1. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string743 = /Set\-Killdate/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string744 = /Set\-MacAttribute\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string745 = /Set\-MasterBootRecord\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string746 = /Set\-ServiceBinPath/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string747 = /Set\-WorkingHours/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string748 = /SharpTemplateResources\/cmd\// nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string749 = /smb_eternalblue/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string750 = /smb1_anonymous_connect_ipc/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string751 = /smb1_anonymous_login/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string752 = /\-SMBExec/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string753 = /SMBNTLMChallenge/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string754 = /SMBNTLMResponse/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string755 = /SMBRelayChallenge/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string756 = /SMBRelayResponse/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string757 = /SnifferSpoofer/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string758 = /SpooferHostsIgnore/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string759 = /SpooferHostsReply/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string760 = /SpooferIP/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string761 = /SpooferIPsIgnore/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string762 = /SpooferIPsReply/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string763 = /SpooferLearningDelay/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string764 = /SpooferLearningInterval/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string765 = /SpooferRepeat/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string766 = /Stage\-gSharedInfoBitmap/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string767 = /stagers\/.{0,100}\/aes\.py/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string768 = /stagers\/.{0,100}\/diffiehellman\.py/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string769 = /stagers\/.{0,100}\/get_sysinfo\.py/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string770 = /stagers\/.{0,100}\/rc4\.py/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string771 = /StarkillerSnackbar\.vue/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string772 = /Start\-MonitorTCPConnections\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string773 = /Start\-ProcessAsUser/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string774 = /Start\-ProcessAsUser\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string775 = /Start\-TCPMonitor/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string776 = /Start\-WebcamRecorder\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string777 = /StopInveigh/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string778 = /sync\-starkiller/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string779 = /Test\-ServiceDaclPermission/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string780 = /tree_connect_andx_request/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string781 = /Update\-ExeFunctions/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string782 = /uselistener\sdbx/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string783 = /uselistener\sonedrive/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string784 = /usemodule\spersistence\// nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string785 = /usemodule\spowershell\/persistence/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string786 = /usemodule\sprivesc\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string787 = /useplugin\scsharpserver/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string788 = /user\sInveigh/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string789 = /usestager\s.{0,100}backdoor/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string790 = /usestager\s.{0,100}ducky/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string791 = /usestager\s.{0,100}launcher_bat/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string792 = /usestager\s.{0,100}launcher_lnk/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string793 = /usestager\s.{0,100}shellcode/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string794 = /usestager\smulti\/launcher/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string795 = /WindowsEnum\s\-/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string796 = /Write\-CMDServiceBinary/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string797 = /Write\-HijackDll/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string798 = /Write\-HijackDll/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string799 = /Write\-HijackDll/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string800 = /Write\-PrivescCheckAsciiReport/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string801 = /Write\-ServiceEXE\s/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string802 = /Write\-ServiceEXECMD/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string803 = /Write\-UserAddServiceBinary/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string804 = /WScriptBypassUAC/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string805 = /ZABvAHcAcwBCAHUAaQBsAHQASQBuAFIAbwBsAGUAXQAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAJwApACkAIAAtACAAJAAoAEcAZQB0AC0ARABhAHQAZQApACIAIAB8ACAATwB1AHQALQBGAGkAbABlACAAQwA6AFwAVQBBAEMAQgB5AHAAYQBzAHMAVABlAHMAdAAuAHQAeAB0ACAALQBBAHAAcABlAG4AZAA/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
