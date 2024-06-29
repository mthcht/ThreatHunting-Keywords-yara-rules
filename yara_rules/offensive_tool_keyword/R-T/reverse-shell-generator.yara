rule reverse_shell_generator
{
    meta:
        description = "Detection patterns for the tool 'reverse-shell-generator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reverse-shell-generator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string1 = /\sperl\-reverse\-shell\s\-\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string2 = /\sreverse_shell_generator/ nocase ascii wide
        // Description: Hosted Reverse Shell generator with a ton of functionality
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string3 = /\sreverse_shell_generator/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string4 = /\swindows\/shell\/bind_tcp\s.{0,1000}shellcode/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string5 = /\"\-c\s\\\"sh\s\-i\s\>\&\s\/dev\/tcp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string6 = /\.revshells\.com/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string7 = /\/ncat\s.{0,1000}\s\-e\ssh/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string8 = /\/Reverse\sShell\sTab\s\-\-\>/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string9 = /\/reverse\.exe/ nocase ascii wide
        // Description: Hosted Reverse Shell generator with a ton of functionality
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string10 = /\/reverse\-shell\-generator/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string11 = /\/reverse\-shell\-generator\.git/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string12 = /\/revshells\.com/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string13 = /\\nc\.exe\s.{0,1000}\s\-e\ssh/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string14 = /\\reverse\.exe/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string15 = /\>JSP\sBackdoor\sReverse\sShell\</ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string16 = /0\<\&196\;exec\s196\<\>\/dev\/tcp\/.{0,1000}\/.{0,1000}\;\ssh\s\<\&196\s\>\&196\s2\>\&196/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string17 = /0dayCTF\/reverse\-shell\-generator/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string18 = /android\/meterpreter\/reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string19 = /apple_ios\/aarch64\/meterpreter_reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string20 = /awk\s\'BEGIN\s\{s\s\=\s\"\/inet\/tcp\/0\/.{0,1000}\"\;.{0,1000}printf\s\"shell\>\"\s\|\&\ss\;.{0,1000}getline.{0,1000}print\s\$0\s\|\&\ss\;.{0,1000}close.{0,1000}\}\'\s\/dev\/null/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string21 = /busybox\snc\s.{0,1000}\s\-e\ssh/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string22 = /class\sReverseBash/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string23 = /cmd\/unix\/reverse_bash/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string24 = /cmd\/unix\/reverse_python/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string25 = /crystal\seval\s\'require\s\"process\"\;require\s\"socket\"\;.{0,1000}Socket\.tcp.{0,1000}connect.{0,1000}Process\.new.{0,1000}output\.gets_to_end/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string26 = /curl\s\-Ns\stelnet\:\/\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string27 = /echo\s\'import\sos\'.{0,1000}echo.{0,1000}os\.system\(\"nc\s\-e\ssh.{0,1000}\'.{0,1000}\s\>\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string28 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\"tcp\".{0,1000}exec\.Command\(\"\/bin\/bash\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string29 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\"tcp\".{0,1000}exec\.Command\(\"\/bin\/sh\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string30 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\"tcp\".{0,1000}exec\.Command\(\"bash\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string31 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\"tcp\".{0,1000}exec\.Command\(\"cmd\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string32 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\"tcp\".{0,1000}exec\.Command\(\"powershell\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string33 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\"tcp\".{0,1000}exec\.Command\(\"pwsh\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string34 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\"tcp\".{0,1000}exec\.Command\(\"sh\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string35 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\"tcp\".{0,1000}exec\.Command\(\"zsh\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string36 = /exec\s5\<\>\/dev\/tcp\/.{0,1000}\/.{0,1000}\;cat\s\<\&5\s\|\swhile\sread\sline\;\sdo\s\$line\s2\>\&5\s\>\&5\;\sdone/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string37 = /export\sRHOST\=.{0,1000}export\sRPORT\=.{0,1000}python3\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}os\.getenv\(\"RHOST\"\).{0,1000}pty\.spawn\(\"sh\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string38 = /import\s\'dart\:io\'\;.{0,1000}Socket\.connect\(.{0,1000}\,\s.{0,1000}Process\.start\(\'sh\'\,\s\[\]\).{0,1000}socket\.write\(output\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string39 = /Invoke\-ConPtyShell\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string40 = /Invoke\-ConPtyShell\.ps1/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string41 = /JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwAC4AMQAwACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBu/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string42 = /java\/jsp_shell_reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string43 = /java\/shell_reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string44 = /linux\/x64\/meterpreter\/reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string45 = /linux\/x64\/shell_reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string46 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\"\/bin\/bash\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string47 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\"\/bin\/sh\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string48 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\"bash\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string49 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\"cmd\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string50 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\"powershell\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string51 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\"pwsh\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string52 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\"zsh\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string53 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'sh\s\-i\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string54 = /lua5\.1\s\-e.{0,1000}require\(\"socket\"\).{0,1000}tcp\:connect.{0,1000}io\.popen.{0,1000}receive\(\).{0,1000}send\(\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string55 = /msfvenom\s\-p\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string56 = /Net\.Sockets\.TCPClient.{0,1000}Net\.Security\.SslStream.{0,1000}AuthenticateAsClient.{0,1000}Invoke\-Expression.{0,1000}Out\-String/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string57 = /Online\s\-\sReverse\sShell\sGenerator/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string58 = /osx\/x64\/meterpreter\/reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string59 = /osx\/x64\/meterpreter_reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string60 = /osx\/x64\/shell_reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string61 = /pentestmonkey\/php\-reverse\-shell/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string62 = /pentestmonkey\@pentestmonkey\.net/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string63 = /perl\s\-e\s\'use\sSocket\;\$.{0,1000}\;socket\(S\,PF_INET\,SOCK_STREAM\,getprotobyname/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string64 = /perl\s\-MIO\s\-e\s.{0,1000}new\sIO\:\:Socket\:\:INET\(PeerAddr\,\".{0,1000}\:.{0,1000}\"\)\;STDIN\-\>fdopen\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string65 = /PHP\sMeterpreter\sStageless\sReverse\sTCP/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string66 = /php\s\-r\s\'\$s\=socket_create\(AF_INET\,SOCK_STREAM\,SOL_TCP\)\;socket_bind\(\$s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string67 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}\)\;exec\(\"sh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string68 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}\)\;passthru\(\"sh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string69 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}\)\;popen\(\"sh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string70 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}\)\;shell_exec\(\"sh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string71 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}\)\;system\(\"sh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string72 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}proc_open\(\"sh\"\,/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string73 = /php\/meterpreter_reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string74 = /php\/reverse_php/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string75 = /php\-reverse\-shell\.php/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string76 = /python\s\-c.{0,1000}\'import\ssocket\,subprocess\,os\'.{0,1000}socket\.socket\(socket\.AF_INET.{0,1000}connect\(\(\".{0,1000}\)\).{0,1000}dup2.{0,1000}pty\.spawn\(\"sh\"\)\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string77 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\"\/bin\/bash\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string78 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\"\/bin\/sh\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string79 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\"bash\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string80 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\"cmd\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string81 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\"powershell\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string82 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\"pwsh\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string83 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\"sh\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string84 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\"zsh\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string85 = /python.{0,1000}\s\-c\s\'import\sos\,pty\,socket.{0,1000}socket\.socket\(\).{0,1000}s\.connect\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string86 = /python.{0,1000}\s\-c\s\'import\ssocket\,subprocess\,os\;.{0,1000}socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\).{0,1000}\.connect\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string87 = /python3\s\-m\spwncat\s\-lp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string88 = /python3\s\-m\spwncat\s\-m\swindows\s\-lp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string89 = /rcat\sconnect\s\-s\ssh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string90 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\"\/bin\/bash\"\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string91 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\"\/bin\/sh\"\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string92 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\"bash\"\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string93 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\"cmd\"\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string94 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\"powershell\"\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string95 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\"pwsh\"\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string96 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\"zsh\"\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string97 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\ssh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string98 = /revsockaddr\.sin_addr\.s_addr\s\=\sinet_addr\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string99 = /rm\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\s\|\ssh\s\-i\s2\>\&1\s\|\snc\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string100 = /rm\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|sh\s\-i\s2\>\&1\|nc\s.{0,1000}\s\>\/tmp\/f/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string101 = /rm\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|sh\s\-i\s2\>\&1\|ncat\s\-u\s.{0,1000}\s\>\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string102 = /ruby\s\-rsocket\s\-e.{0,1000}TCPSocket\.new.{0,1000}loop.{0,1000}gets.{0,1000}chomp.{0,1000}IO\.popen.{0,1000}read/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string103 = /ruby\s\-rsocket\s\-e\'spawn\(\"\/bin\/bash\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string104 = /ruby\s\-rsocket\s\-e\'spawn\(\"\/bin\/sh\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string105 = /ruby\s\-rsocket\s\-e\'spawn\(\"bash\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string106 = /ruby\s\-rsocket\s\-e\'spawn\(\"cmd\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string107 = /ruby\s\-rsocket\s\-e\'spawn\(\"powershell\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string108 = /ruby\s\-rsocket\s\-e\'spawn\(\"pwsh\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string109 = /ruby\s\-rsocket\s\-e\'spawn\(\"sh\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string110 = /ruby\s\-rsocket\s\-e\'spawn\(\"zsh\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string111 = /Runtime\.getRuntime\(\)\.exec\(\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s\/bin\/bash\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string112 = /Runtime\.getRuntime\(\)\.exec\(\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s\/bin\/sh\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string113 = /Runtime\.getRuntime\(\)\.exec\(\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\sbash\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string114 = /Runtime\.getRuntime\(\)\.exec\(\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\scmd\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string115 = /Runtime\.getRuntime\(\)\.exec\(\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\spowershell\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string116 = /Runtime\.getRuntime\(\)\.exec\(\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\spwsh\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string117 = /Runtime\.getRuntime\(\)\.exec\(\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\szsh\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string118 = /Runtime\.getRuntime\(\)\.exec\(\"bash\s\-c.{0,1000}\s\/dev\/tcp\/.{0,1000}\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string119 = /sh\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string120 = /sh\s\-i\s\>\&\s\/dev\/udp\/.{0,1000}\/.{0,1000}\s0\>\&1/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string121 = /sh\s\-i\s5\<\>\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\<\&5\s1\>\&5\s2\>\&5/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string122 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\"\/bin\/bash\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string123 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\"\/bin\/sh\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string124 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\"bash\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string125 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\"cmd\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string126 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\"powershell\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string127 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\"pwsh\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string128 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\"zsh\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string129 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:sh/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string130 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\'sh/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string131 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\"\/bin\/bash\"\s\|\snc.{0,1000}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string132 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\"\/bin\/sh\"\s\|\snc.{0,1000}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string133 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\"bash\"\s\|\snc.{0,1000}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string134 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\"cmd\"\s\|\snc.{0,1000}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string135 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\"powershell\"\s\|\snc.{0,1000}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string136 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\"pwsh\"\s\|\snc.{0,1000}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string137 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\"zsh\"\s\|\snc.{0,1000}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string138 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|sh\s\-i.{0,1000}\|nc.{0,1000}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string139 = /struct\ssockaddr_in\srevsockaddr/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string140 = /stty\sraw\s\-echo\;\s\(stty\ssize\;\scat\)\s\|\snc\s\-lvnp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string141 = /System\.Net\.Sockets\.TCPClient.{0,1000}GetStream\(\).{0,1000}iex.{0,1000}Out\-String/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string142 = /Windows\sBind\sTCP\sShellCode\s\-\sBOF/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string143 = /Windows\sMeterpreter\sStaged\sReverse\sTCP\s\(x64/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string144 = /Windows\sMeterpreter\sStageless\sReverse\sTCP\s\(x64\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string145 = /Windows\sStaged\sJSP\sReverse\sTCP/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string146 = /Windows\sStaged\sReverse\sTCP\s\(x64\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string147 = /Windows\sStageless\sReverse\sTCP\s\(x64\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string148 = /windows\/x64\/meterpreter\/reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string149 = /windows\/x64\/meterpreter_reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string150 = /windows\/x64\/meterpreter_reverse_tcp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string151 = /windows\/x64\/shell_reverse_tcp/ nocase ascii wide

    condition:
        any of them
}
