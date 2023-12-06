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
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string2 = /\s\\Temp\\blah\.exe/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string3 = /\s\-AgentDelay\s/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string4 = /\s\-AgentJitter\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string5 = /\s\-bootkey\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string6 = /\s\-ChildPath\s.{0,1000}fodhelper\.exe/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string7 = /\s\-ChildPath\s.{0,1000}sdclt\.exe/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string8 = /\s\-CollectionMethod\sstealth/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string9 = /\s\-ComputerName\s\-ServiceEXE\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string10 = /\s\-ConType\sbind\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string11 = /\s\-ConType\sreverse\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string12 = /\s\-CShardDLLBytes/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string13 = /\s\-DllName\s.{0,1000}\s\-FunctionName\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string14 = /\s\-Domain\s.{0,1000}\s\-SMB1\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string15 = /\s\-DoNotPersistImmediately\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string16 = /\s\-DumpCerts\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string17 = /\s\-DumpCreds\s/ nocase ascii wide
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
        $string22 = /\s\-Enumerate\s.{0,1000}\s\-Module\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string23 = /\s\-ExeArguments\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string24 = /\s\-FullPrivs\s.{0,1000}\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string25 = /\s\-GHUser\s.{0,1000}\s\-GHRepo\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string26 = /\s\-Hosts\s.{0,1000}\s\-TopPorts\s/ nocase ascii wide
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
        $string35 = /\s\-LNKPath\s.{0,1000}\s\-EncScript\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string36 = /\s\-mDNSTTL\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string37 = /\s\-NBNSTTL\s/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string38 = /\s\-NoBase64\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string39 = /\s\-NoP\s\-sta\s\-NonI\s\-W\sHidden\s\-Enc\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string40 = /\s\-p\s1337:1337\s\-p\s5000:5000/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string41 = /\s\-PasswordList\s/ nocase ascii wide
        // Description: Empire scripts arguments. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string42 = /\s\-payload\s.{0,1000}\-Lhost\s.{0,1000}\-Lport/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string43 = /\s\-PayloadPath\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string44 = /\s\-PEPath\s.{0,1000}\s\-ExeArgs\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string45 = /\s\-PermanentWMI\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string46 = /\s\-PersistenceScriptName\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string47 = /\s\-PersistentScriptFilePath\s/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string48 = /\s\-\-port\s1337/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string49 = /\s\-Registry\s\-AtStartup\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string50 = /\s\-RemoteDllHandle\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string51 = /\s\-RevToSelf\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string52 = /\s\-Rhost\s.{0,1000}\s\-WARFile\shttp/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string53 = /\s\-Rhosts\s.{0,1000}\s\-Password\s.{0,1000}\s\-Directory\s.{0,1000}\s\-Dictionary\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string54 = /\s\-Rhosts\s.{0,1000}\s\-Path\s.{0,1000}\.txt\s\-Port\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string55 = /\s\-ScheduledTask\s\-OnIdle\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string56 = /\s\-ServiceName\s.{0,1000}\s\-PipeName\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string57 = /\s\-SiteListFilePath\s.{0,1000}\s\-B64Pass\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string58 = /\s\-SpooferIP\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string59 = /\s\-Target\s.{0,1000}\s\-AllDomain\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string60 = /\s\-Target\s.{0,1000}\s\-InitialGrooms\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string61 = /\s\-Target\s.{0,1000}\s\-Shellcode\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string62 = /\s\-type\suser\s\-search\s.{0,1000}\s\-DomainController\s.{0,1000}\s\-Credential\s.{0,1000}\s\-list\syes/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string63 = /\s\-Username\s.{0,1000}\s\-Hash\s.{0,1000}\s\-Command\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string64 = /\s\-UserPersistenceOption\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string65 = /\s\-VaultElementPtr\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string66 = /\swindows\/csharp_exe/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string67 = /\s\-WorkingHours\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string68 = /\sYour\spayload\shas\sbeen\sdelivered/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string69 = /\/\/localhost:1337/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string70 = /\/api\/admin\/shutdown\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string71 = /\/api\/agents\/.{0,1000}\/kill\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string72 = /\/api\/agents\/all\/kill\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string73 = /\/api\/agents\/all\/shell\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string74 = /\/api\/agents\/CXPLDTZCKFNT3SLT\/shell\?/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string75 = /\/api\/agents\/stale\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string76 = /\/api\/agents\/XMY2H2ZPFWNPGEAP\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string77 = /\/api\/listeners\/all\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string78 = /\/api\/modules\/collection\/.{0,1000}\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string79 = /\/api\/modules\/credentials.{0,1000}\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string80 = /\/api\/reporting\/agent\/initial\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string81 = /\/api\/reporting\/msg\/.{0,1000}\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string82 = /\/api\/reporting\/type\/checkin\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string83 = /\/api\/stagers\/dll\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string84 = /\/api\/stagers\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string85 = /\/api\/users\/1\/disable\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string86 = /\/api\/v2\/starkiller/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string87 = /\/client\/generated\-stagers\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string88 = /\/data\/empire\.db/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string89 = /\/download\-stager\.js/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string90 = /\/ducky\.py/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string91 = /\/Empire\.git/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string92 = /\/empire\/client\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string93 = /\/empire:latest/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string94 = /\/EmpireProject/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string95 = /\/evilhost:/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string96 = /\/hop\.php/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string97 = /\/HTTP\-Login\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string98 = /\/Invoke\-RunAs\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string99 = /\/lateral_movement\// nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string100 = /\/lateral_movement\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string101 = /\/MailRaider\.ps1/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string102 = /\/network\/bloodhound3/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string103 = /\/persistence\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string104 = /\/persistence\/.{0,1000}\.psm1/ nocase ascii wide
        // Description: Empire power tools like powerview powerbreach powerpick powerup
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string105 = /\/PowerTools/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string106 = /\/privesc\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string107 = /\/ps\-empire/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string108 = /\/ReferenceSourceLibraries\/Sharpire/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string109 = /\/server\/common\/stagers\.py/ nocase ascii wide
        // Description: Empire executable paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string110 = /\/situational_awareness\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string111 = /\/situational_awareness\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string112 = /\/smb\/psexec\.rb/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string113 = /\/stagers\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string114 = /\/stagers\/CSharpPS/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string115 = /\/tools\/psexec\.rb/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string116 = /\/trollsploit\// nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string117 = /\/x64_slim\.dll/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string118 = /\/xar\-1\.5\.2\.tar\.gz/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string119 = /\\hijackers\\/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string120 = /1337.{0,1000}\/api\/agents\/.{0,1000}\/results\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string121 = /1337.{0,1000}\/api\/creds\?token\=/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string122 = /1337.{0,1000}\/api\/listeners\?token\=/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string123 = /ACBypassTest/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string124 = /Add\-Persistence/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string125 = /Add\-PSFirewallRules/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string126 = /bc\-security\/empire/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string127 = /BC\-SECURITY\/Starkiller/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string128 = /Bitmap\-Elevate/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string129 = /BloodHound\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string130 = /Building\sSYSTEM\simpersonation/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string131 = /BypassUACTokenManipulation/ nocase ascii wide
        // Description: Empire dll paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string132 = /code_execution\/.{0,1000}\.dll/ nocase ascii wide
        // Description: Empire executable paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string133 = /code_execution\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string134 = /code_execution\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string135 = /ConvertFrom\-LDAPLogonHours/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string136 = /ConvertTo\-LogonHoursArray/ nocase ascii wide
        // Description: empire function name. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string137 = /ConvertTo\-Rc4ByteStream/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string138 = /Create\-NamedPipe/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string139 = /Create\-SuspendedWinLogon/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string140 = /Create\-WinLogonProcess/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string141 = /csharp_inject_bof_inject/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string142 = /Decode\-RoutingPacket/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string143 = /Decrypt\-Bytes/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string144 = /Decrypt\-CipherText/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string145 = /DecryptNextCharacterWinSCP/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string146 = /DecryptWinSCPPassword/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string147 = /\-DllInjection\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string148 = /\-DllName\s.{0,1000}\-Module\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string149 = /Do\-AltShiftEsc/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string150 = /Do\-AltShiftTab/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string151 = /\-Domain\s.{0,1000}\s\-AllowDelegation\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string152 = /\-Domain\s.{0,1000}\s\-SPN\s/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string153 = /download\s.{0,1000}bloodhound/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string154 = /DownloadAndExtractFromRemoteRegistry/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string155 = /dumpCredStore\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string156 = /\-DumpForest\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string157 = /echo\s.{0,1000}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string158 = /egresscheck\-framework/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string159 = /ElevatePrivs/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string160 = /Empire\sFramework\sGUI/ nocase ascii wide
        // Description: empire command lines patterns
        // Reference: https://github.com/EmpireProject/Empire
        $string161 = /empire\s\-\-rest\s/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string162 = /empire\s\-\-server\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string163 = /empire\/client\/.{0,1000}\.py/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string164 = /empire\/server\/.{0,1000}\.py/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string165 = /empire\/server\/downloads\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string166 = /empire\/server\/downloads\/logs\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string167 = /empire_server\./ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string168 = /empireadmin/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string169 = /empire\-chain\.pem/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string170 = /EmpireCORSMiddleware/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string171 = /Empire\-GUI\.git/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string172 = /Empire\-master/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string173 = /empire\-priv\.key/ nocase ascii wide
        // Description: Empire is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent. and a pure Python 2.6/2.7 Linux/OS X agent. It is the merge of the previous PowerShell Empire and Python EmPyre projects. The framework offers cryptologically-secure communications and a flexible architecture. On the PowerShell side. Empire implements the ability to run PowerShell agents without needing powershell.exe. rapidly deployable post-exploitation modules ranging from key loggers to Mimikatz. and adaptable communications to evade network detection. all wrapped up in a usability-focused framework. PowerShell Empire premiered at BSidesLV in 2015 and Python EmPyre premeiered at HackMiami 2016.
        // Reference: https://github.com/EmpireProject/Empire
        $string174 = /EmpireProject/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string175 = /Empire\-Sponsors\.git/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string176 = /empire\-test\-kalirolling/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string177 = /Enable\-SeAssignPrimaryTokenPrivilege/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string178 = /Enable\-SeDebugPrivilege/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string179 = /Encrypt\-Bytes/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string180 = /Enum\-Creds/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string181 = /EternalBlue\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string182 = /\-EventVwrBypass/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string183 = /ExfilDataToGitHub/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string184 = /ExfilDataToGitHub/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string185 = /Exploit\-JBoss\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string186 = /Exploit\-JBoss\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string187 = /Exploit\-JBoss\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string188 = /Exploit\-Jenkins/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string189 = /Exploit\-Jenkins\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string190 = /Exploit\-JMXConsole/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string191 = /Export\-PowerViewCSV/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string192 = /Find\-4624Logons/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string193 = /Find\-4648Logons/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string194 = /Find\-AppLockerLogs/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string195 = /Find\-DomainShare\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string196 = /Find\-DomainShare\s\-CheckShareAccess/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string197 = /Find\-Fruit\./ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string198 = /Find\-Fruit\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string199 = /Find\-InterestingDomainAcl/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string200 = /Find\-InterestingDomainShareFile/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string201 = /Find\-KeePassconfig/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string202 = /Find\-LocalAdminAccess/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string203 = /Find\-PathDLLHijack/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string204 = /Find\-ProcessDLLHijack/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string205 = /Find\-PSScriptsInPSAppLog/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string206 = /Find\-RDPClientConnections/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string207 = /Find\-TrustedDocuments/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string208 = /Find\-TrustedDocuments\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string209 = /Find\-UserField\s\-SearchField\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string210 = /Find\-WMILocalAdminAccess/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string211 = /function\spsenum/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string212 = /generate_powershell_exe/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string213 = /generate_powershell_shellcode/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string214 = /generate_python_exe/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string215 = /generate_python_shellcode/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string216 = /generate_stageless/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string217 = /Get\-ActiveTCPConnections/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string218 = /Get\-BloodHoundData/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string219 = /Get\-BootKey/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string220 = /Get\-BrowserData\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string221 = /Get\-BrowserInformation/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string222 = /Get\-CachedGPPPassword/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string223 = /Get\-ChromeBookmarks/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string224 = /Get\-ChromeDump/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string225 = /Get\-ChromeDump/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string226 = /Get\-ChromeHistory/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string227 = /Get\-ClipboardContents/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string228 = /Get\-ClipboardContents\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string229 = /GetComputersFromActiveDirectory/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string230 = /Get\-DCBadPwdCount/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string231 = /Get\-DecryptedCpassword/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string232 = /Get\-DecryptedSitelistPassword/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string233 = /Get\-DomainDFSShareV1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string234 = /Get\-DomainDFSShareV2/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string235 = /Get\-DomainManagedSecurityGroup/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string236 = /Get\-DomainObjectACL\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string237 = /Get\-DomainSearcher/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string238 = /Get\-DomainSpn/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string239 = /Get\-DomainSPNTicket/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string240 = /Get\-DomainSPNTicket/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string241 = /Get\-FireFoxHistory/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string242 = /Get\-FoxDump/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string243 = /Get\-FoxDump/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string244 = /Get\-GPPInnerFields/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string245 = /Get\-GPPPassword/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string246 = /Get\-GPPPassword\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string247 = /Get\-ImageNtHeaders/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string248 = /Get\-InternetExplorerBookmarks/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string249 = /Get\-InternetExplorerHistory/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string250 = /Get\-KeePassDatabaseKey/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string251 = /Get\-KeePassINIFields/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string252 = /Get\-KeePassXMLFields/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string253 = /Get\-Keystrokes/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string254 = /Get\-Killdate/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string255 = /Get\-LastLoggedon\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string256 = /Get\-LoggedOnLocal\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string257 = /Get\-ModifiableRegistryAutoRun/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string258 = /Get\-ModifiableScheduledTaskFile/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string259 = /Get\-NetComputer\s\-Unconstrainuser/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string260 = /Get\-NetFileServer/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string261 = /Get\-NetForestDomain/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string262 = /Get\-NetLoggedon\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string263 = /Get\-NetRDPSession\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string264 = /Get\-NetUser\s\-SPN/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string265 = /Get\-NetUser\s\-UACFilter\sNOT_ACCOUNTDISABLE/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string266 = /Get\-PacketNetBIOSSessionService/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string267 = /Get\-PacketNTLMSSPAuth/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string268 = /Get\-PacketNTLMSSPNegotiate/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string269 = /Get\-PacketRPCBind/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string270 = /Get\-PacketRPCRequest/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string271 = /Get\-PacketSMB/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string272 = /Get\-PEBasicInfo/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string273 = /Get\-RegistryAlwaysInstallElevated/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string274 = /Get\-RegistryAutoLogon/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string275 = /Get\-RickAstley/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string276 = /Get\-RickAstley\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string277 = /Get\-SecurityPackages\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string278 = /Get\-SitelistFields/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string279 = /Get\-SiteListPassword/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string280 = /Get\-SiteListPassword/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string281 = /Get\-SiteListPassword/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string282 = /Get\-SPN\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string283 = /Get\-SQLInstanceDomain/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string284 = /Get\-SQLInstanceDomain\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string285 = /Get\-SQLServerLoginDefaultPw/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string286 = /Get\-SQLServerLoginDefaultPw/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string287 = /Get\-SQLSysadminCheck/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string288 = /Get\-System\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string289 = /Get\-SystemDNSServer\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string290 = /Get\-SystemNamedPipe/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string291 = /Get\-USBKeystrokes/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string292 = /Get\-UserBadPwdCount/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string293 = /Get\-VaultCredential/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string294 = /Get\-VaultCredential\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string295 = /Get\-WMIRegCachedRDPConnection/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string296 = /Get\-WMIRegLastLoggedOn/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string297 = /Get\-WMIRegMountedDrive/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string298 = /Get\-WorkingHours/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string299 = /Honey\shash/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string300 = /http.{0,1000}\/127\.0\.0\.1.{0,1000}:1337/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string301 = /http.{0,1000}\/localhost.{0,1000}:1337/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string302 = /http_malleable\.py/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string303 = /HTTP\-Login\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string304 = /ImportDll::GetAsyncKeyState/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string305 = /Import\-DllImports/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string306 = /Import\-DllInRemoteProcess/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string307 = /Import\-DllInRemoteProcess/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string308 = /Inject\-BypassStuff/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string309 = /injected\sinto\sLSASS/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string310 = /Injection.{0,1000}\s\-ProcName\slsass/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string311 = /Inject\-LocalShellcode/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string312 = /Inject\-RemoteShellcode/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string313 = /install\s\spowershell\-empire/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string314 = /Install\-ServiceBinary/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string315 = /Install\-SSP\s\-Path.{0,1000}\.dll/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string316 = /Install\-SSP\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string317 = /\-Inveigh\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string318 = /Inveigh\sRelay/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string319 = /inveigh_version/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string320 = /\-InveighRelay\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string321 = /invoke\sobfuscation/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string322 = /Invoke\-ARPScan/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string323 = /Invoke\-ARPScan\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string324 = /Invoke\-BackdoorLNK/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string325 = /Invoke\-BackdoorLNK/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string326 = /Invoke\-BypassUAC/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string327 = /Invoke\-BypassUAC/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string328 = /Invoke\-CallbackIEX/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string329 = /Invoke\-ClipboardMonitor/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string330 = /Invoke\-CredentialInjection/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string331 = /Invoke\-CredentialInjection/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string332 = /Invoke\-DCOM\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string333 = /Invoke\-DCSync/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string334 = /Invoke\-DllInjection/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string335 = /Invoke\-EgressCheck/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string336 = /Invoke\-EgressCheck\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string337 = /Invoke\-Empire\s/ nocase ascii wide
        // Description: empire function name of agent.ps1. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string338 = /Invoke\-Empire/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string339 = /Invoke\-EnumerateLocalAdmin/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string340 = /Invoke\-EnvBypass/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string341 = /Invoke\-EnvBypass\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string342 = /Invoke\-EventVwrBypass/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string343 = /Invoke\-ExecuteMSBuild/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string344 = /Invoke\-ExecuteMSBuild\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string345 = /Invoke\-FodHelperBypass/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string346 = /Invoke\-FodHelperBypass/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string347 = /Invoke\-ImpersonateUser/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string348 = /Invoke\-Inveigh/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string349 = /Invoke\-InveighRelay\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string350 = /Invoke\-Kerberoast/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string351 = /Invoke\-Kerberoast/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string352 = /Invoke\-MS16032/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string353 = /Invoke\-MS16032/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string354 = /Invoke\-MS16135/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string355 = /Invoke\-MS16135\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string356 = /Invoke\-NetRipper/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string357 = /Invoke\-NinjaCopy/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string358 = /Invoke\-NinjaCopy/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string359 = /Invoke\-Ntsd\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string360 = /Invoke\-PacketKnock/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string361 = /Invoke\-Paranoia/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string362 = /Invoke\-Paranoia/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string363 = /Invoke\-PatchDll/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string364 = /Invoke\-PatchDll/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string365 = /Invoke\-PatchDll/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string366 = /Invoke\-PortBind/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string367 = /Invoke\-Portscan/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string368 = /Invoke\-Portscan\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string369 = /Invoke\-PostExfil/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string370 = /Invoke\-PostExfil/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string371 = /Invoke\-PowerDump/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string372 = /Invoke\-PowerDump/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string373 = /Invoke\-PsExec/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string374 = /Invoke\-PsExec\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string375 = /Invoke\-PSInject/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string376 = /Invoke\-PSInject\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string377 = /Invoke\-ReflectivePEInjection/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string378 = /Invoke\-ReflectivePEInjection/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string379 = /Invoke\-ReflectivePEInjection/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string380 = /Invoke\-ReflectivePEInjection/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string381 = /Invoke\-SDCLTBypass/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string382 = /Invoke\-ServiceAbuse/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string383 = /Invoke\-SessionGopher/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string384 = /Invoke\-SessionGopher/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string385 = /Invoke\-Shellcode\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string386 = /Invoke\-ShellcodeMSIL/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string387 = /Invoke\-ShellCommand/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string388 = /Invoke\-SMBAutoBrute/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string389 = /Invoke\-SMBAutoBrute/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string390 = /Invoke\-SMBExec\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string391 = /Invoke\-SMBScanner/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string392 = /Invoke\-SmbScanner/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string393 = /Invoke\-SmbScanner/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string394 = /Invoke\-SQLOSCmd\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string395 = /Invoke\-SQLOSCmd\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string396 = /Invoke\-SSHCommand\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string397 = /Invoke\-Tater\./ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string398 = /Invoke\-Tater\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string399 = /Invoke\-ThreadedFunction/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string400 = /Invoke\-TokenManipulation\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string401 = /Invoke\-UserHunter/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string402 = /Invoke\-UserImpersonation/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string403 = /Invoke\-Vnc/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string404 = /Invoke\-Vnc\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string405 = /Invoke\-VoiceTroll\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string406 = /Invoke\-WinEnum/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string407 = /Invoke\-WinEnum\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string408 = /Invoke\-WScriptBypassUAC/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string409 = /Invoke\-WscriptElevate/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string410 = /KeePassConfig\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string411 = /\-KeePassConfigTrigger/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string412 = /KeeThief\./ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string413 = /KeeThief\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string414 = /keyword_obfuscation/ nocase ascii wide
        // Description: empire script command. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string415 = /Kicking\soff\sdownload\scradle\sin\sa\snew\sprocess/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string416 = /Killed\srunning\seventvwr/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string417 = /Killed\srunning\ssdclt/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string418 = /Launch\sEmpire\sCLI/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string419 = /Launch\sEmpire\sServer/ nocase ascii wide
        // Description: Empire scripts argument. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string420 = /ListMetasploitPayloads/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string421 = /LLMNRSpoofer/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string422 = /Local:Get\-DelegateType/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string423 = /Local:Get\-PEArchitecture/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string424 = /Local:Get\-ProcAddress/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string425 = /make_kernel_shellcode/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string426 = /make_kernel_user_payload/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string427 = /make_smb1_anonymous_login_packet/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string428 = /make_smb1_echo_packet/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string429 = /make_smb1_free_hole_session_packet/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string430 = /make_smb1_nt_trans_packet/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string431 = /make_smb1_trans2_explo/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string432 = /make_smb2_payload_body_packet/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string433 = /make_smb2_payload_headers_packet/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string434 = /MalleableProfiles\.vue/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string435 = /mDNSSpoofer/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string436 = /MetasploitPayload\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string437 = /NBNSBruteForceHost/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string438 = /NBNSBruteForcePause/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string439 = /NBNSBruteForceSpoofer/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string440 = /NBNSBruteForceTarget/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string441 = /NBNSSpoofer/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string442 = /New\-ElevatedPersistenceOption/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string443 = /New\-HoneyHash/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string444 = /New\-HoneyHash\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string445 = /New\-InMemoryModule\s\-ModuleName\sWin32/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string446 = /New\-InMemoryModule/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string447 = /New\-InMemoryModule/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string448 = /New\-RoutingPacket/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string449 = /New\-UserPersistenceOption/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string450 = /NTLMChallengeBase64/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string451 = /NTLMChallengeBase64/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string452 = /obfuscate_command/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string453 = /obfuscated_module_source\// nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string454 = /Out\-Minidump\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string455 = /Persistence\.psm1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string456 = /Persistence\.psm1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string457 = /port_forward_pivot\.py/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string458 = /PowerBreach\.ps1/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string459 = /powershell_code_execution_invoke_assembly/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string460 = /powershell_collection_keylogger/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string461 = /powershell_collection_screenshot/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string462 = /powershell_credentials_tokens/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string463 = /powershell_management_psinject/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string464 = /powershell_management_spawn/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string465 = /powershell_privesc_bypassuac_eventvwr/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string466 = /powershell_privesc_sherlock/ nocase ascii wide
        // Description: PowerShell offers a multitude of offensive advantages. including full .NET access. application whitelisting. direct access to the Win32 API. the ability to assemble malicious binaries in memory. and a default installation on Windows 7+. Offensive PowerShell had a watershed year in 2014. but despite the multitude of useful projects. many pentesters still struggle to integrate PowerShell into their engagements in a secure manner.
        // Reference: https://www.powershellempire.com/
        $string467 = /PowerShellEmpire/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string468 = /PowerUp\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string469 = /PowerUp\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string470 = /powerview\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string471 = /ProcessFileZillaFile/ nocase ascii wide
        // Description: empire script arguments Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string472 = /\-ProcessID\s.{0,1000}\s\-Dll\s.{0,1000}\s\-Module\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string473 = /ProcessPPKFile/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string474 = /ProcessPuTTYLocal/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string475 = /ProcessRDPFile/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string476 = /ProcessRDPLocal/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string477 = /ProcessSuperPuTTYFile/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string478 = /Process\-TaskingPackets/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string479 = /ProcessThoroughLocal/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string480 = /ProcessThoroughRemote/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string481 = /ProcessWinSCPLocal/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string482 = /ps\-empire\sclient/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string483 = /ps\-empire\sserver/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string484 = /ps\-empire/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string485 = /\-PsExecCmd/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string486 = /\-PWDumpFormat/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string487 = /python_modules\/keyboard\.zip/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string488 = /Receive\-AgentJob/ nocase ascii wide
        // Description: Empire dll paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string489 = /ReflectivePick_x64_orig\.dll/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string490 = /ReflectivePick_x86_orig\.dll/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string491 = /\-Rhost\s.{0,1000}\s\-Port\s.{0,1000}\s\-Cmd\s.{0,1000}cmd\s\/c/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string492 = /Running\sfinal\sexploit\spacket/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string493 = /Send\sthe\spayload\swith\sthe\sgrooms/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string494 = /server\/modules\/csharp\// nocase ascii wide
        // Description: empire command lines patterns
        // Reference: https://github.com/EmpireProject/Empire
        $string495 = /set\sCertPath\sdata\// nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string496 = /set\sCollectionMethodAll/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string497 = /Set\sListener\sdbx/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string498 = /set\sListener\sonedrive/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string499 = /set\sProfile\sapt1\.profile/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string500 = /Set\-DesktopACLToAllow/ nocase ascii wide
        // Description: empire function name of agent.ps1. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string501 = /Set\-Killdate/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string502 = /Set\-MacAttribute\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string503 = /Set\-ServiceBinPath/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string504 = /Set\-WorkingHours/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string505 = /SharpTemplateResources\/cmd\// nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string506 = /smb_eternalblue/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string507 = /smb1_anonymous_connect_ipc/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string508 = /smb1_anonymous_login/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string509 = /\-SMBExec/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string510 = /SMBNTLMChallenge/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string511 = /SMBNTLMChallenge/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string512 = /SMBNTLMResponse/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string513 = /SMBRelayChallenge/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string514 = /SMBRelayResponse/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string515 = /SnifferSpoofer/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string516 = /SpooferHostsIgnore/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string517 = /SpooferHostsReply/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string518 = /SpooferIP/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string519 = /SpooferIPsIgnore/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string520 = /SpooferIPsReply/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string521 = /SpooferLearningDelay/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string522 = /SpooferLearningInterval/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string523 = /SpooferRepeat/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string524 = /Stage\-gSharedInfoBitmap/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string525 = /stagers\/.{0,1000}\/aes\.py/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string526 = /stagers\/.{0,1000}\/diffiehellman\.py/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string527 = /stagers\/.{0,1000}\/get_sysinfo\.py/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string528 = /stagers\/.{0,1000}\/rc4\.py/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string529 = /StarkillerSnackbar\.vue/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string530 = /Start\-MonitorTCPConnections\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string531 = /Start\-TCPMonitor/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string532 = /StopInveigh/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string533 = /sync\-starkiller/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string534 = /Test\-ServiceDaclPermission/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string535 = /tree_connect_andx_request/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string536 = /Update\-ExeFunctions/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string537 = /uselistener\sdbx/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string538 = /uselistener\sonedrive/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string539 = /usemodule\spersistence\// nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string540 = /usemodule\spowershell\/persistence/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string541 = /usemodule\sprivesc\// nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string542 = /useplugin\scsharpserver/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string543 = /user\sInveigh/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string544 = /usestager\s/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string545 = /usestager\s.{0,1000}backdoor/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string546 = /usestager\s.{0,1000}ducky/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string547 = /usestager\s.{0,1000}launcher_bat/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string548 = /usestager\s.{0,1000}launcher_lnk/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string549 = /usestager\s.{0,1000}shellcode/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string550 = /usestager\smulti\/launcher/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string551 = /WindowsEnum\s\-/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string552 = /Write\-HijackDll/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string553 = /Write\-HijackDll/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string554 = /WScriptBypassUAC/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string555 = /psenum\s/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string556 = /psinject/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string557 = /uselistener\shttp/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string558 = /usemodule\s.{0,1000}\// nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string559 = /usestager\s/ nocase ascii wide

    condition:
        any of them
}
