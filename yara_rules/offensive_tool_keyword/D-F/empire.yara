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
        $string1 = /.{0,1000}\s\$FodHelperPath.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string2 = /.{0,1000}\s\\Temp\\blah\.exe.{0,1000}/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string3 = /.{0,1000}\s\-AgentDelay\s.{0,1000}/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string4 = /.{0,1000}\s\-AgentJitter\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string5 = /.{0,1000}\s\-bootkey\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string6 = /.{0,1000}\s\-ChildPath\s.{0,1000}fodhelper\.exe.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string7 = /.{0,1000}\s\-ChildPath\s.{0,1000}sdclt\.exe.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string8 = /.{0,1000}\s\-CollectionMethod\sstealth.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string9 = /.{0,1000}\s\-ComputerName\s\-ServiceEXE\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string10 = /.{0,1000}\s\-ConType\sbind\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string11 = /.{0,1000}\s\-ConType\sreverse\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string12 = /.{0,1000}\s\-CShardDLLBytes.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string13 = /.{0,1000}\s\-DllName\s.{0,1000}\s\-FunctionName\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string14 = /.{0,1000}\s\-Domain\s.{0,1000}\s\-SMB1\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string15 = /.{0,1000}\s\-DoNotPersistImmediately\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string16 = /.{0,1000}\s\-DumpCerts\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string17 = /.{0,1000}\s\-DumpCreds\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string18 = /.{0,1000}\s\-ElevatedPersistenceOption\s.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string19 = /.{0,1000}\sempire\.arguments.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string20 = /.{0,1000}\sempire\.client\..{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string21 = /.{0,1000}\sempire\.py.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string22 = /.{0,1000}\s\-Enumerate\s.{0,1000}\s\-Module\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string23 = /.{0,1000}\s\-ExeArguments\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string24 = /.{0,1000}\s\-FullPrivs\s.{0,1000}\s/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string25 = /.{0,1000}\s\-GHUser\s.{0,1000}\s\-GHRepo\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string26 = /.{0,1000}\s\-Hosts\s.{0,1000}\s\-TopPorts\s.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string27 = /.{0,1000}\shttp_malleable.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string28 = /.{0,1000}\s\-ImpersonateUser\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string29 = /.{0,1000}\s\-ImportDllPathPtr\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string30 = /.{0,1000}\sInveigh\-.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string31 = /.{0,1000}\s\-JMXConsole\s\-AppName\s.{0,1000}/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string32 = /.{0,1000}\s\-KillDate\s.{0,1000}/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string33 = /.{0,1000}\s\-KillDays\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string34 = /.{0,1000}\s\-LLMNRTTL\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string35 = /.{0,1000}\s\-LNKPath\s.{0,1000}\s\-EncScript\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string36 = /.{0,1000}\s\-mDNSTTL\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string37 = /.{0,1000}\s\-NBNSTTL\s.{0,1000}/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string38 = /.{0,1000}\s\-NoBase64\s.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string39 = /.{0,1000}\s\-NoP\s\-sta\s\-NonI\s\-W\sHidden\s\-Enc\s.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string40 = /.{0,1000}\s\-p\s1337:1337\s\-p\s5000:5000.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string41 = /.{0,1000}\s\-PasswordList\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts arguments. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string42 = /.{0,1000}\s\-payload\s.{0,1000}\-Lhost\s.{0,1000}\-Lport.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string43 = /.{0,1000}\s\-PayloadPath\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string44 = /.{0,1000}\s\-PEPath\s.{0,1000}\s\-ExeArgs\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string45 = /.{0,1000}\s\-PermanentWMI\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string46 = /.{0,1000}\s\-PersistenceScriptName\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string47 = /.{0,1000}\s\-PersistentScriptFilePath\s.{0,1000}/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string48 = /.{0,1000}\s\-\-port\s1337.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string49 = /.{0,1000}\s\-Registry\s\-AtStartup\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string50 = /.{0,1000}\s\-RemoteDllHandle\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string51 = /.{0,1000}\s\-RevToSelf\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string52 = /.{0,1000}\s\-Rhost\s.{0,1000}\s\-WARFile\shttp.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string53 = /.{0,1000}\s\-Rhosts\s.{0,1000}\s\-Password\s.{0,1000}\s\-Directory\s.{0,1000}\s\-Dictionary\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string54 = /.{0,1000}\s\-Rhosts\s.{0,1000}\s\-Path\s.{0,1000}\.txt\s\-Port\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string55 = /.{0,1000}\s\-ScheduledTask\s\-OnIdle\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string56 = /.{0,1000}\s\-ServiceName\s.{0,1000}\s\-PipeName\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string57 = /.{0,1000}\s\-SiteListFilePath\s.{0,1000}\s\-B64Pass\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string58 = /.{0,1000}\s\-SpooferIP\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string59 = /.{0,1000}\s\-Target\s.{0,1000}\s\-AllDomain\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string60 = /.{0,1000}\s\-Target\s.{0,1000}\s\-InitialGrooms\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string61 = /.{0,1000}\s\-Target\s.{0,1000}\s\-Shellcode\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string62 = /.{0,1000}\s\-type\suser\s\-search\s.{0,1000}\s\-DomainController\s.{0,1000}\s\-Credential\s.{0,1000}\s\-list\syes.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string63 = /.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s.{0,1000}\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string64 = /.{0,1000}\s\-UserPersistenceOption\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string65 = /.{0,1000}\s\-VaultElementPtr\s.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string66 = /.{0,1000}\swindows\/csharp_exe.{0,1000}/ nocase ascii wide
        // Description: empire agent.ps1 arguments.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string67 = /.{0,1000}\s\-WorkingHours\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string68 = /.{0,1000}\sYour\spayload\shas\sbeen\sdelivered.{0,1000}/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string69 = /.{0,1000}\/\/localhost:1337.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string70 = /.{0,1000}\/api\/admin\/shutdown\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string71 = /.{0,1000}\/api\/agents\/.{0,1000}\/kill\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string72 = /.{0,1000}\/api\/agents\/all\/kill\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string73 = /.{0,1000}\/api\/agents\/all\/shell\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string74 = /.{0,1000}\/api\/agents\/CXPLDTZCKFNT3SLT\/shell\?.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string75 = /.{0,1000}\/api\/agents\/stale\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string76 = /.{0,1000}\/api\/agents\/XMY2H2ZPFWNPGEAP\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string77 = /.{0,1000}\/api\/listeners\/all\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string78 = /.{0,1000}\/api\/modules\/collection\/.{0,1000}\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string79 = /.{0,1000}\/api\/modules\/credentials.{0,1000}\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string80 = /.{0,1000}\/api\/reporting\/agent\/initial\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string81 = /.{0,1000}\/api\/reporting\/msg\/.{0,1000}\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string82 = /.{0,1000}\/api\/reporting\/type\/checkin\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string83 = /.{0,1000}\/api\/stagers\/dll\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string84 = /.{0,1000}\/api\/stagers\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string85 = /.{0,1000}\/api\/users\/1\/disable\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string86 = /.{0,1000}\/api\/v2\/starkiller.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string87 = /.{0,1000}\/client\/generated\-stagers\/.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string88 = /.{0,1000}\/data\/empire\.db.{0,1000}/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string89 = /.{0,1000}\/download\-stager\.js.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string90 = /.{0,1000}\/ducky\.py/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string91 = /.{0,1000}\/Empire\.git/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string92 = /.{0,1000}\/empire\/client\/.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string93 = /.{0,1000}\/empire:latest.{0,1000}/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string94 = /.{0,1000}\/EmpireProject.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string95 = /.{0,1000}\/evilhost:.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string96 = /.{0,1000}\/hop\.php.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string97 = /.{0,1000}\/HTTP\-Login\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string98 = /.{0,1000}\/Invoke\-RunAs\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string99 = /.{0,1000}\/lateral_movement\/.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string100 = /.{0,1000}\/lateral_movement\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string101 = /.{0,1000}\/MailRaider\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string102 = /.{0,1000}\/network\/bloodhound3.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string103 = /.{0,1000}\/persistence\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string104 = /.{0,1000}\/persistence\/.{0,1000}\.psm1/ nocase ascii wide
        // Description: Empire power tools like powerview powerbreach powerpick powerup
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string105 = /.{0,1000}\/PowerTools.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string106 = /.{0,1000}\/privesc\/.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string107 = /.{0,1000}\/ps\-empire.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string108 = /.{0,1000}\/ReferenceSourceLibraries\/Sharpire.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string109 = /.{0,1000}\/server\/common\/stagers\.py.{0,1000}/ nocase ascii wide
        // Description: Empire executable paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string110 = /.{0,1000}\/situational_awareness\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string111 = /.{0,1000}\/situational_awareness\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string112 = /.{0,1000}\/smb\/psexec\.rb.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string113 = /.{0,1000}\/stagers\/.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string114 = /.{0,1000}\/stagers\/CSharpPS.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string115 = /.{0,1000}\/tools\/psexec\.rb.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string116 = /.{0,1000}\/trollsploit\/.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string117 = /.{0,1000}\/x64_slim\.dll.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string118 = /.{0,1000}\/xar\-1\.5\.2\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string119 = /.{0,1000}\\hijackers\\.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string120 = /.{0,1000}1337.{0,1000}\/api\/agents\/.{0,1000}\/results\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string121 = /.{0,1000}1337.{0,1000}\/api\/creds\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string122 = /.{0,1000}1337.{0,1000}\/api\/listeners\?token\=.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string123 = /.{0,1000}ACBypassTest.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string124 = /.{0,1000}Add\-Persistence.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string125 = /.{0,1000}Add\-PSFirewallRules.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string126 = /.{0,1000}bc\-security\/empire.{0,1000}/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string127 = /.{0,1000}BC\-SECURITY\/Starkiller.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string128 = /.{0,1000}Bitmap\-Elevate.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string129 = /.{0,1000}BloodHound\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string130 = /.{0,1000}Building\sSYSTEM\simpersonation.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string131 = /.{0,1000}BypassUACTokenManipulation.{0,1000}/ nocase ascii wide
        // Description: Empire dll paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string132 = /.{0,1000}code_execution\/.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Empire executable paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string133 = /.{0,1000}code_execution\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string134 = /.{0,1000}code_execution\/.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string135 = /.{0,1000}ConvertFrom\-LDAPLogonHours.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string136 = /.{0,1000}ConvertTo\-LogonHoursArray.{0,1000}/ nocase ascii wide
        // Description: empire function name. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string137 = /.{0,1000}ConvertTo\-Rc4ByteStream.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string138 = /.{0,1000}Create\-NamedPipe.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string139 = /.{0,1000}Create\-SuspendedWinLogon.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string140 = /.{0,1000}Create\-WinLogonProcess.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string141 = /.{0,1000}csharp_inject_bof_inject.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string142 = /.{0,1000}Decode\-RoutingPacket.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string143 = /.{0,1000}Decrypt\-Bytes.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string144 = /.{0,1000}Decrypt\-CipherText.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string145 = /.{0,1000}DecryptNextCharacterWinSCP.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string146 = /.{0,1000}DecryptWinSCPPassword.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string147 = /.{0,1000}\-DllInjection\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string148 = /.{0,1000}\-DllName\s.{0,1000}\-Module\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string149 = /.{0,1000}Do\-AltShiftEsc.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string150 = /.{0,1000}Do\-AltShiftTab.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string151 = /.{0,1000}\-Domain\s.{0,1000}\s\-AllowDelegation\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string152 = /.{0,1000}\-Domain\s.{0,1000}\s\-SPN\s.{0,1000}/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string153 = /.{0,1000}download\s.{0,1000}bloodhound.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string154 = /.{0,1000}DownloadAndExtractFromRemoteRegistry.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string155 = /.{0,1000}dumpCredStore\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string156 = /.{0,1000}\-DumpForest\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string157 = /.{0,1000}echo\s.{0,1000}\s\>\s\\\\\.\\pipe\\.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string158 = /.{0,1000}egresscheck\-framework.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string159 = /.{0,1000}ElevatePrivs.{0,1000}/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string160 = /.{0,1000}Empire\sFramework\sGUI.{0,1000}/ nocase ascii wide
        // Description: empire command lines patterns
        // Reference: https://github.com/EmpireProject/Empire
        $string161 = /.{0,1000}empire\s\-\-rest\s.{0,1000}/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string162 = /.{0,1000}empire\s\-\-server\s.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string163 = /.{0,1000}empire\/client\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string164 = /.{0,1000}empire\/server\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string165 = /.{0,1000}empire\/server\/downloads\/.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string166 = /.{0,1000}empire\/server\/downloads\/logs\/.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string167 = /.{0,1000}empire_server\..{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string168 = /.{0,1000}empireadmin.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string169 = /.{0,1000}empire\-chain\.pem.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string170 = /.{0,1000}EmpireCORSMiddleware.{0,1000}/ nocase ascii wide
        // Description: The Empire Multiuser GUI is a graphical interface to the Empire post-exploitation Framework
        // Reference: https://github.com/EmpireProject/Empire-GUI
        $string171 = /.{0,1000}Empire\-GUI\.git.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string172 = /.{0,1000}Empire\-master.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string173 = /.{0,1000}empire\-priv\.key.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent. and a pure Python 2.6/2.7 Linux/OS X agent. It is the merge of the previous PowerShell Empire and Python EmPyre projects. The framework offers cryptologically-secure communications and a flexible architecture. On the PowerShell side. Empire implements the ability to run PowerShell agents without needing powershell.exe. rapidly deployable post-exploitation modules ranging from key loggers to Mimikatz. and adaptable communications to evade network detection. all wrapped up in a usability-focused framework. PowerShell Empire premiered at BSidesLV in 2015 and Python EmPyre premeiered at HackMiami 2016.
        // Reference: https://github.com/EmpireProject/Empire
        $string174 = /.{0,1000}EmpireProject.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string175 = /.{0,1000}Empire\-Sponsors\.git.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string176 = /.{0,1000}empire\-test\-kalirolling.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string177 = /.{0,1000}Enable\-SeAssignPrimaryTokenPrivilege.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string178 = /.{0,1000}Enable\-SeDebugPrivilege.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string179 = /.{0,1000}Encrypt\-Bytes.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string180 = /.{0,1000}Enum\-Creds.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string181 = /.{0,1000}EternalBlue\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string182 = /.{0,1000}\-EventVwrBypass.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string183 = /.{0,1000}ExfilDataToGitHub.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string184 = /.{0,1000}ExfilDataToGitHub.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string185 = /.{0,1000}Exploit\-JBoss\s\-.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string186 = /.{0,1000}Exploit\-JBoss\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string187 = /.{0,1000}Exploit\-JBoss\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string188 = /.{0,1000}Exploit\-Jenkins.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string189 = /.{0,1000}Exploit\-Jenkins\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string190 = /.{0,1000}Exploit\-JMXConsole.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string191 = /.{0,1000}Export\-PowerViewCSV.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string192 = /.{0,1000}Find\-4624Logons.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string193 = /.{0,1000}Find\-4648Logons.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string194 = /.{0,1000}Find\-AppLockerLogs.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string195 = /.{0,1000}Find\-DomainShare\s\-.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string196 = /.{0,1000}Find\-DomainShare\s\-CheckShareAccess.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string197 = /.{0,1000}Find\-Fruit\..{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string198 = /.{0,1000}Find\-Fruit\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string199 = /.{0,1000}Find\-InterestingDomainAcl.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string200 = /.{0,1000}Find\-InterestingDomainShareFile.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string201 = /.{0,1000}Find\-KeePassconfig.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string202 = /.{0,1000}Find\-LocalAdminAccess.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string203 = /.{0,1000}Find\-PathDLLHijack.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string204 = /.{0,1000}Find\-ProcessDLLHijack.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string205 = /.{0,1000}Find\-PSScriptsInPSAppLog.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string206 = /.{0,1000}Find\-RDPClientConnections.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string207 = /.{0,1000}Find\-TrustedDocuments.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string208 = /.{0,1000}Find\-TrustedDocuments\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string209 = /.{0,1000}Find\-UserField\s\-SearchField\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string210 = /.{0,1000}Find\-WMILocalAdminAccess.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string211 = /.{0,1000}function\spsenum.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string212 = /.{0,1000}generate_powershell_exe.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string213 = /.{0,1000}generate_powershell_shellcode.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string214 = /.{0,1000}generate_python_exe.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string215 = /.{0,1000}generate_python_shellcode.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string216 = /.{0,1000}generate_stageless.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string217 = /.{0,1000}Get\-ActiveTCPConnections.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string218 = /.{0,1000}Get\-BloodHoundData.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string219 = /.{0,1000}Get\-BootKey.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string220 = /.{0,1000}Get\-BrowserData\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string221 = /.{0,1000}Get\-BrowserInformation.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string222 = /.{0,1000}Get\-CachedGPPPassword.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string223 = /.{0,1000}Get\-ChromeBookmarks.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string224 = /.{0,1000}Get\-ChromeDump.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string225 = /.{0,1000}Get\-ChromeDump.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string226 = /.{0,1000}Get\-ChromeHistory.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string227 = /.{0,1000}Get\-ClipboardContents.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string228 = /.{0,1000}Get\-ClipboardContents\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string229 = /.{0,1000}GetComputersFromActiveDirectory.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string230 = /.{0,1000}Get\-DCBadPwdCount.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string231 = /.{0,1000}Get\-DecryptedCpassword.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string232 = /.{0,1000}Get\-DecryptedSitelistPassword.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string233 = /.{0,1000}Get\-DomainDFSShareV1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string234 = /.{0,1000}Get\-DomainDFSShareV2.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string235 = /.{0,1000}Get\-DomainManagedSecurityGroup.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string236 = /.{0,1000}Get\-DomainObjectACL\s\-.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string237 = /.{0,1000}Get\-DomainSearcher.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string238 = /.{0,1000}Get\-DomainSpn.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string239 = /.{0,1000}Get\-DomainSPNTicket.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string240 = /.{0,1000}Get\-DomainSPNTicket.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string241 = /.{0,1000}Get\-FireFoxHistory.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string242 = /.{0,1000}Get\-FoxDump.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string243 = /.{0,1000}Get\-FoxDump.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string244 = /.{0,1000}Get\-GPPInnerFields.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string245 = /.{0,1000}Get\-GPPPassword.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string246 = /.{0,1000}Get\-GPPPassword\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string247 = /.{0,1000}Get\-ImageNtHeaders.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string248 = /.{0,1000}Get\-InternetExplorerBookmarks.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string249 = /.{0,1000}Get\-InternetExplorerHistory.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string250 = /.{0,1000}Get\-KeePassDatabaseKey.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string251 = /.{0,1000}Get\-KeePassINIFields.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string252 = /.{0,1000}Get\-KeePassXMLFields.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string253 = /.{0,1000}Get\-Keystrokes.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string254 = /.{0,1000}Get\-Killdate.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string255 = /.{0,1000}Get\-LastLoggedon\s\-.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string256 = /.{0,1000}Get\-LoggedOnLocal\s\-.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string257 = /.{0,1000}Get\-ModifiableRegistryAutoRun.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string258 = /.{0,1000}Get\-ModifiableScheduledTaskFile.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string259 = /.{0,1000}Get\-NetComputer\s\-Unconstrainuser.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string260 = /.{0,1000}Get\-NetFileServer.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string261 = /.{0,1000}Get\-NetForestDomain.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string262 = /.{0,1000}Get\-NetLoggedon\s\-.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string263 = /.{0,1000}Get\-NetRDPSession\s\-.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string264 = /.{0,1000}Get\-NetUser\s\-SPN.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string265 = /.{0,1000}Get\-NetUser\s\-UACFilter\sNOT_ACCOUNTDISABLE.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string266 = /.{0,1000}Get\-PacketNetBIOSSessionService.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string267 = /.{0,1000}Get\-PacketNTLMSSPAuth.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string268 = /.{0,1000}Get\-PacketNTLMSSPNegotiate.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string269 = /.{0,1000}Get\-PacketRPCBind.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string270 = /.{0,1000}Get\-PacketRPCRequest.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string271 = /.{0,1000}Get\-PacketSMB.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string272 = /.{0,1000}Get\-PEBasicInfo.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string273 = /.{0,1000}Get\-RegistryAlwaysInstallElevated.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string274 = /.{0,1000}Get\-RegistryAutoLogon.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string275 = /.{0,1000}Get\-RickAstley.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string276 = /.{0,1000}Get\-RickAstley\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string277 = /.{0,1000}Get\-SecurityPackages\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string278 = /.{0,1000}Get\-SitelistFields.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string279 = /.{0,1000}Get\-SiteListPassword.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string280 = /.{0,1000}Get\-SiteListPassword.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string281 = /.{0,1000}Get\-SiteListPassword.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string282 = /.{0,1000}Get\-SPN\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string283 = /.{0,1000}Get\-SQLInstanceDomain.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string284 = /.{0,1000}Get\-SQLInstanceDomain\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string285 = /.{0,1000}Get\-SQLServerLoginDefaultPw.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string286 = /.{0,1000}Get\-SQLServerLoginDefaultPw.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string287 = /.{0,1000}Get\-SQLSysadminCheck.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string288 = /.{0,1000}Get\-System\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string289 = /.{0,1000}Get\-SystemDNSServer\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string290 = /.{0,1000}Get\-SystemNamedPipe.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string291 = /.{0,1000}Get\-USBKeystrokes.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string292 = /.{0,1000}Get\-UserBadPwdCount.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string293 = /.{0,1000}Get\-VaultCredential.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string294 = /.{0,1000}Get\-VaultCredential\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string295 = /.{0,1000}Get\-WMIRegCachedRDPConnection.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string296 = /.{0,1000}Get\-WMIRegLastLoggedOn.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string297 = /.{0,1000}Get\-WMIRegMountedDrive.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string298 = /.{0,1000}Get\-WorkingHours.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string299 = /.{0,1000}Honey\shash.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string300 = /.{0,1000}http.{0,1000}\/127\.0\.0\.1.{0,1000}:1337.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string301 = /.{0,1000}http.{0,1000}\/localhost.{0,1000}:1337.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string302 = /.{0,1000}http_malleable\.py.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string303 = /.{0,1000}HTTP\-Login\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string304 = /.{0,1000}ImportDll::GetAsyncKeyState.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string305 = /.{0,1000}Import\-DllImports.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string306 = /.{0,1000}Import\-DllInRemoteProcess.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string307 = /.{0,1000}Import\-DllInRemoteProcess.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string308 = /.{0,1000}Inject\-BypassStuff.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string309 = /.{0,1000}injected\sinto\sLSASS.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string310 = /.{0,1000}Injection.{0,1000}\s\-ProcName\slsass.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string311 = /.{0,1000}Inject\-LocalShellcode.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string312 = /.{0,1000}Inject\-RemoteShellcode.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string313 = /.{0,1000}install\s\spowershell\-empire.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string314 = /.{0,1000}Install\-ServiceBinary.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string315 = /.{0,1000}Install\-SSP\s\-Path.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string316 = /.{0,1000}Install\-SSP\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string317 = /.{0,1000}\-Inveigh\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string318 = /.{0,1000}Inveigh\sRelay.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string319 = /.{0,1000}inveigh_version.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string320 = /.{0,1000}\-InveighRelay\s.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string321 = /.{0,1000}invoke\sobfuscation.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string322 = /.{0,1000}Invoke\-ARPScan.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string323 = /.{0,1000}Invoke\-ARPScan\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string324 = /.{0,1000}Invoke\-BackdoorLNK.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string325 = /.{0,1000}Invoke\-BackdoorLNK.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string326 = /.{0,1000}Invoke\-BypassUAC.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string327 = /.{0,1000}Invoke\-BypassUAC.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string328 = /.{0,1000}Invoke\-CallbackIEX.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string329 = /.{0,1000}Invoke\-ClipboardMonitor.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string330 = /.{0,1000}Invoke\-CredentialInjection.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string331 = /.{0,1000}Invoke\-CredentialInjection.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string332 = /.{0,1000}Invoke\-DCOM\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string333 = /.{0,1000}Invoke\-DCSync.{0,1000}/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string334 = /.{0,1000}Invoke\-DllInjection.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string335 = /.{0,1000}Invoke\-EgressCheck.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string336 = /.{0,1000}Invoke\-EgressCheck\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string337 = /.{0,1000}Invoke\-Empire\s.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string338 = /.{0,1000}Invoke\-Empire.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string339 = /.{0,1000}Invoke\-EnumerateLocalAdmin.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string340 = /.{0,1000}Invoke\-EnvBypass.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string341 = /.{0,1000}Invoke\-EnvBypass\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string342 = /.{0,1000}Invoke\-EventVwrBypass.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string343 = /.{0,1000}Invoke\-ExecuteMSBuild.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string344 = /.{0,1000}Invoke\-ExecuteMSBuild\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string345 = /.{0,1000}Invoke\-FodHelperBypass.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string346 = /.{0,1000}Invoke\-FodHelperBypass.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string347 = /.{0,1000}Invoke\-ImpersonateUser.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string348 = /.{0,1000}Invoke\-Inveigh.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string349 = /.{0,1000}Invoke\-InveighRelay\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string350 = /.{0,1000}Invoke\-Kerberoast.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string351 = /.{0,1000}Invoke\-Kerberoast.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string352 = /.{0,1000}Invoke\-MS16032.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string353 = /.{0,1000}Invoke\-MS16032.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string354 = /.{0,1000}Invoke\-MS16135.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string355 = /.{0,1000}Invoke\-MS16135\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string356 = /.{0,1000}Invoke\-NetRipper.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string357 = /.{0,1000}Invoke\-NinjaCopy.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string358 = /.{0,1000}Invoke\-NinjaCopy.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string359 = /.{0,1000}Invoke\-Ntsd\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string360 = /.{0,1000}Invoke\-PacketKnock.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string361 = /.{0,1000}Invoke\-Paranoia.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string362 = /.{0,1000}Invoke\-Paranoia.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string363 = /.{0,1000}Invoke\-PatchDll.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string364 = /.{0,1000}Invoke\-PatchDll.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string365 = /.{0,1000}Invoke\-PatchDll.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string366 = /.{0,1000}Invoke\-PortBind.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string367 = /.{0,1000}Invoke\-Portscan.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string368 = /.{0,1000}Invoke\-Portscan\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string369 = /.{0,1000}Invoke\-PostExfil.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string370 = /.{0,1000}Invoke\-PostExfil.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string371 = /.{0,1000}Invoke\-PowerDump.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string372 = /.{0,1000}Invoke\-PowerDump.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string373 = /.{0,1000}Invoke\-PsExec.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string374 = /.{0,1000}Invoke\-PsExec\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string375 = /.{0,1000}Invoke\-PSInject.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string376 = /.{0,1000}Invoke\-PSInject\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string377 = /.{0,1000}Invoke\-ReflectivePEInjection.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string378 = /.{0,1000}Invoke\-ReflectivePEInjection.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string379 = /.{0,1000}Invoke\-ReflectivePEInjection.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string380 = /.{0,1000}Invoke\-ReflectivePEInjection.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string381 = /.{0,1000}Invoke\-SDCLTBypass.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string382 = /.{0,1000}Invoke\-ServiceAbuse.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string383 = /.{0,1000}Invoke\-SessionGopher.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string384 = /.{0,1000}Invoke\-SessionGopher.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string385 = /.{0,1000}Invoke\-Shellcode\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string386 = /.{0,1000}Invoke\-ShellcodeMSIL.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string387 = /.{0,1000}Invoke\-ShellCommand.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string388 = /.{0,1000}Invoke\-SMBAutoBrute.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string389 = /.{0,1000}Invoke\-SMBAutoBrute.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string390 = /.{0,1000}Invoke\-SMBExec\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string391 = /.{0,1000}Invoke\-SMBScanner.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string392 = /.{0,1000}Invoke\-SmbScanner.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string393 = /.{0,1000}Invoke\-SmbScanner.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string394 = /.{0,1000}Invoke\-SQLOSCmd\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string395 = /.{0,1000}Invoke\-SQLOSCmd\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string396 = /.{0,1000}Invoke\-SSHCommand\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string397 = /.{0,1000}Invoke\-Tater\..{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string398 = /.{0,1000}Invoke\-Tater\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string399 = /.{0,1000}Invoke\-ThreadedFunction.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string400 = /.{0,1000}Invoke\-TokenManipulation\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string401 = /.{0,1000}Invoke\-UserHunter.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string402 = /.{0,1000}Invoke\-UserImpersonation.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string403 = /.{0,1000}Invoke\-Vnc.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string404 = /.{0,1000}Invoke\-Vnc\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string405 = /.{0,1000}Invoke\-VoiceTroll\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string406 = /.{0,1000}Invoke\-WinEnum.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string407 = /.{0,1000}Invoke\-WinEnum\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string408 = /.{0,1000}Invoke\-WScriptBypassUAC.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string409 = /.{0,1000}Invoke\-WscriptElevate.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string410 = /.{0,1000}KeePassConfig\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string411 = /.{0,1000}\-KeePassConfigTrigger.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string412 = /.{0,1000}KeeThief\..{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string413 = /.{0,1000}KeeThief\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string414 = /.{0,1000}keyword_obfuscation.{0,1000}/ nocase ascii wide
        // Description: empire script command. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string415 = /.{0,1000}Kicking\soff\sdownload\scradle\sin\sa\snew\sprocess.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string416 = /.{0,1000}Killed\srunning\seventvwr.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string417 = /.{0,1000}Killed\srunning\ssdclt.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string418 = /.{0,1000}Launch\sEmpire\sCLI.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string419 = /.{0,1000}Launch\sEmpire\sServer.{0,1000}/ nocase ascii wide
        // Description: Empire scripts argument. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string420 = /.{0,1000}ListMetasploitPayloads.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string421 = /.{0,1000}LLMNRSpoofer.{0,1000}/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string422 = /.{0,1000}Local:Get\-DelegateType.{0,1000}/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string423 = /.{0,1000}Local:Get\-PEArchitecture.{0,1000}/ nocase ascii wide
        // Description: empire script function. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string424 = /.{0,1000}Local:Get\-ProcAddress.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string425 = /.{0,1000}make_kernel_shellcode.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string426 = /.{0,1000}make_kernel_user_payload.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string427 = /.{0,1000}make_smb1_anonymous_login_packet.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string428 = /.{0,1000}make_smb1_echo_packet.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string429 = /.{0,1000}make_smb1_free_hole_session_packet.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string430 = /.{0,1000}make_smb1_nt_trans_packet.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string431 = /.{0,1000}make_smb1_trans2_explo.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string432 = /.{0,1000}make_smb2_payload_body_packet.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string433 = /.{0,1000}make_smb2_payload_headers_packet.{0,1000}/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string434 = /.{0,1000}MalleableProfiles\.vue.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string435 = /.{0,1000}mDNSSpoofer.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string436 = /.{0,1000}MetasploitPayload\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string437 = /.{0,1000}NBNSBruteForceHost.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string438 = /.{0,1000}NBNSBruteForcePause.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string439 = /.{0,1000}NBNSBruteForceSpoofer.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string440 = /.{0,1000}NBNSBruteForceTarget.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string441 = /.{0,1000}NBNSSpoofer.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string442 = /.{0,1000}New\-ElevatedPersistenceOption.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string443 = /.{0,1000}New\-HoneyHash.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string444 = /.{0,1000}New\-HoneyHash\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string445 = /.{0,1000}New\-InMemoryModule\s\-ModuleName\sWin32.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string446 = /.{0,1000}New\-InMemoryModule.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string447 = /.{0,1000}New\-InMemoryModule.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string448 = /.{0,1000}New\-RoutingPacket.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string449 = /.{0,1000}New\-UserPersistenceOption.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string450 = /.{0,1000}NTLMChallengeBase64.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string451 = /.{0,1000}NTLMChallengeBase64.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string452 = /.{0,1000}obfuscate_command.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string453 = /.{0,1000}obfuscated_module_source\/.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string454 = /.{0,1000}Out\-Minidump\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string455 = /.{0,1000}Persistence\.psm1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string456 = /.{0,1000}Persistence\.psm1.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string457 = /.{0,1000}port_forward_pivot\.py.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string458 = /.{0,1000}PowerBreach\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string459 = /.{0,1000}powershell_code_execution_invoke_assembly.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string460 = /.{0,1000}powershell_collection_keylogger.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string461 = /.{0,1000}powershell_collection_screenshot.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string462 = /.{0,1000}powershell_credentials_tokens.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string463 = /.{0,1000}powershell_management_psinject.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string464 = /.{0,1000}powershell_management_spawn.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string465 = /.{0,1000}powershell_privesc_bypassuac_eventvwr.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string466 = /.{0,1000}powershell_privesc_sherlock.{0,1000}/ nocase ascii wide
        // Description: PowerShell offers a multitude of offensive advantages. including full .NET access. application whitelisting. direct access to the Win32 API. the ability to assemble malicious binaries in memory. and a default installation on Windows 7+. Offensive PowerShell had a watershed year in 2014. but despite the multitude of useful projects. many pentesters still struggle to integrate PowerShell into their engagements in a secure manner.
        // Reference: https://www.powershellempire.com/
        $string467 = /.{0,1000}PowerShellEmpire.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string468 = /.{0,1000}PowerUp\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string469 = /.{0,1000}PowerUp\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string470 = /.{0,1000}powerview\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string471 = /.{0,1000}ProcessFileZillaFile.{0,1000}/ nocase ascii wide
        // Description: empire script arguments Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string472 = /.{0,1000}\-ProcessID\s.{0,1000}\s\-Dll\s.{0,1000}\s\-Module\s.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string473 = /.{0,1000}ProcessPPKFile.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string474 = /.{0,1000}ProcessPuTTYLocal.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string475 = /.{0,1000}ProcessRDPFile.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string476 = /.{0,1000}ProcessRDPLocal.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string477 = /.{0,1000}ProcessSuperPuTTYFile.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string478 = /.{0,1000}Process\-TaskingPackets.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string479 = /.{0,1000}ProcessThoroughLocal.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string480 = /.{0,1000}ProcessThoroughRemote.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string481 = /.{0,1000}ProcessWinSCPLocal.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string482 = /.{0,1000}ps\-empire\sclient.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string483 = /.{0,1000}ps\-empire\sserver.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string484 = /.{0,1000}ps\-empire.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string485 = /.{0,1000}\-PsExecCmd.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string486 = /.{0,1000}\-PWDumpFormat.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string487 = /.{0,1000}python_modules\/keyboard\.zip.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string488 = /.{0,1000}Receive\-AgentJob.{0,1000}/ nocase ascii wide
        // Description: Empire dll paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string489 = /.{0,1000}ReflectivePick_x64_orig\.dll.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string490 = /.{0,1000}ReflectivePick_x86_orig\.dll.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string491 = /.{0,1000}\-Rhost\s.{0,1000}\s\-Port\s.{0,1000}\s\-Cmd\s.{0,1000}cmd\s\/c.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string492 = /.{0,1000}Running\sfinal\sexploit\spacket.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string493 = /.{0,1000}Send\sthe\spayload\swith\sthe\sgrooms.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string494 = /.{0,1000}server\/modules\/csharp\/.{0,1000}/ nocase ascii wide
        // Description: empire command lines patterns
        // Reference: https://github.com/EmpireProject/Empire
        $string495 = /.{0,1000}set\sCertPath\sdata\/.{0,1000}/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string496 = /.{0,1000}set\sCollectionMethodAll.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string497 = /.{0,1000}Set\sListener\sdbx.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string498 = /.{0,1000}set\sListener\sonedrive.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string499 = /.{0,1000}set\sProfile\sapt1\.profile.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string500 = /.{0,1000}Set\-DesktopACLToAllow.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string501 = /.{0,1000}Set\-Killdate.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string502 = /.{0,1000}Set\-MacAttribute\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string503 = /.{0,1000}Set\-ServiceBinPath.{0,1000}/ nocase ascii wide
        // Description: empire function name of agent.ps1.Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string504 = /.{0,1000}Set\-WorkingHours.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string505 = /.{0,1000}SharpTemplateResources\/cmd\/.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string506 = /.{0,1000}smb_eternalblue.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string507 = /.{0,1000}smb1_anonymous_connect_ipc.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string508 = /.{0,1000}smb1_anonymous_login.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string509 = /.{0,1000}\-SMBExec.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string510 = /.{0,1000}SMBNTLMChallenge.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string511 = /.{0,1000}SMBNTLMChallenge.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string512 = /.{0,1000}SMBNTLMResponse.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string513 = /.{0,1000}SMBRelayChallenge.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string514 = /.{0,1000}SMBRelayResponse.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string515 = /.{0,1000}SnifferSpoofer.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string516 = /.{0,1000}SpooferHostsIgnore.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string517 = /.{0,1000}SpooferHostsReply.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string518 = /.{0,1000}SpooferIP.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string519 = /.{0,1000}SpooferIPsIgnore.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string520 = /.{0,1000}SpooferIPsReply.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string521 = /.{0,1000}SpooferLearningDelay.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string522 = /.{0,1000}SpooferLearningInterval.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string523 = /.{0,1000}SpooferRepeat.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string524 = /.{0,1000}Stage\-gSharedInfoBitmap.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string525 = /.{0,1000}stagers\/.{0,1000}\/aes\.py.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string526 = /.{0,1000}stagers\/.{0,1000}\/diffiehellman\.py.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string527 = /.{0,1000}stagers\/.{0,1000}\/get_sysinfo\.py.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string528 = /.{0,1000}stagers\/.{0,1000}\/rc4\.py.{0,1000}/ nocase ascii wide
        // Description: Starkiller is a Frontend for Powershell Empire. It is a web application written in VueJS
        // Reference: https://github.com/BC-SECURITY/Starkiller
        $string529 = /.{0,1000}StarkillerSnackbar\.vue.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string530 = /.{0,1000}Start\-MonitorTCPConnections\.ps1.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string531 = /.{0,1000}Start\-TCPMonitor.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string532 = /.{0,1000}StopInveigh.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string533 = /.{0,1000}sync\-starkiller.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string534 = /.{0,1000}Test\-ServiceDaclPermission.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string535 = /.{0,1000}tree_connect_andx_request.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string536 = /.{0,1000}Update\-ExeFunctions.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string537 = /.{0,1000}uselistener\sdbx.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string538 = /.{0,1000}uselistener\sonedrive.{0,1000}/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string539 = /.{0,1000}usemodule\spersistence\/.{0,1000}/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string540 = /.{0,1000}usemodule\spowershell\/persistence.{0,1000}/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string541 = /.{0,1000}usemodule\sprivesc\/.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string542 = /.{0,1000}useplugin\scsharpserver.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string543 = /.{0,1000}user\sInveigh.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string544 = /.{0,1000}usestager\s.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string545 = /.{0,1000}usestager\s.{0,1000}backdoor.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string546 = /.{0,1000}usestager\s.{0,1000}ducky.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string547 = /.{0,1000}usestager\s.{0,1000}launcher_bat.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string548 = /.{0,1000}usestager\s.{0,1000}launcher_lnk.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string549 = /.{0,1000}usestager\s.{0,1000}shellcode.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string550 = /.{0,1000}usestager\smulti\/launcher.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string551 = /.{0,1000}WindowsEnum\s\-.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string552 = /.{0,1000}Write\-HijackDll.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string553 = /.{0,1000}Write\-HijackDll.{0,1000}/ nocase ascii wide
        // Description: Empire scripts paths. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string554 = /.{0,1000}WScriptBypassUAC.{0,1000}/ nocase ascii wide
        // Description: Empire scripts functions. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string555 = /psenum\s.{0,1000}/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string556 = /psinject/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string557 = /uselistener\shttp.{0,1000}/ nocase ascii wide
        // Description: Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // Reference: https://github.com/BC-SECURITY/Empire
        $string558 = /usemodule\s.{0,1000}\/.{0,1000}/ nocase ascii wide
        // Description: Empire commands. Empire is an open source. cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python. the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS. Empire was one of five tools singled out by a joint report on public hacking tools being widely used by adversaries
        // Reference: https://github.com/EmpireProject/Empire
        $string559 = /usestager\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
