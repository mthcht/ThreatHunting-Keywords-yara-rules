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
        $string1 = " perl-reverse-shell - " nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string2 = " reverse_shell_generator" nocase ascii wide
        // Description: Hosted Reverse Shell generator with a ton of functionality
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string3 = " reverse_shell_generator" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string4 = /\swindows\/shell\/bind_tcp\s.{0,100}shellcode/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string5 = /\\"\-c\s\\\\"sh\s\-i\s\>\&\s\/dev\/tcp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string6 = /\.revshells\.com/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string7 = /\/ncat\s.{0,100}\s\-e\ssh/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string8 = "/Reverse Shell Tab -->"
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string9 = /\/reverse\.exe/ nocase ascii wide
        // Description: Hosted Reverse Shell generator with a ton of functionality
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string10 = "/reverse-shell-generator" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string11 = /\/reverse\-shell\-generator\.git/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string12 = /\/revshells\.com/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string13 = /\\nc\.exe\s.{0,100}\s\-e\ssh/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string14 = /\\reverse\.exe/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string15 = ">JSP Backdoor Reverse Shell<" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string16 = /0\<\&196\;exec\s196\<\>\/dev\/tcp\/.{0,100}\/.{0,100}\;\ssh\s\<\&196\s\>\&196\s2\>\&196/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string17 = "0dayCTF/reverse-shell-generator" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string18 = "android/meterpreter/reverse_tcp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string19 = "apple_ios/aarch64/meterpreter_reverse_tcp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string20 = /awk\s\'BEGIN\s\{s\s\=\s\\"\/inet\/tcp\/0\/.{0,100}\\"\;.{0,100}printf\s\\"shell\>\\"\s\|\&\ss\;.{0,100}getline.{0,100}print\s\$0\s\|\&\ss\;.{0,100}close.{0,100}\}\'\s\/dev\/null/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string21 = /busybox\snc\s.{0,100}\s\-e\ssh/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string22 = "class ReverseBash"
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string23 = "cmd/unix/reverse_bash"
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string24 = "cmd/unix/reverse_python" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string25 = /crystal\seval\s\'require\s\\"process\\"\;require\s\\"socket\\"\;.{0,100}Socket\.tcp.{0,100}connect.{0,100}Process\.new.{0,100}output\.gets_to_end/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string26 = "curl -Ns telnet://" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string27 = /echo\s\'import\sos\'.{0,100}echo.{0,100}os\.system\(\\"nc\s\-e\ssh.{0,100}\'.{0,100}\s\>\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string28 = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"\/bin\/bash\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\//
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string29 = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"\/bin\/sh\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\//
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string30 = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"bash\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\//
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string31 = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"cmd\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string32 = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"powershell\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string33 = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"pwsh\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string34 = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"sh\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string35 = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"zsh\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string36 = /exec\s5\<\>\/dev\/tcp\/.{0,100}\/.{0,100}\;cat\s\<\&5\s\|\swhile\sread\sline\;\sdo\s\$line\s2\>\&5\s\>\&5\;\sdone/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string37 = /export\sRHOST\=.{0,100}export\sRPORT\=.{0,100}python3\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}os\.getenv\(\\"RHOST\\"\).{0,100}pty\.spawn\(\\"sh\\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string38 = /import\s\'dart\:io\'\;.{0,100}Socket\.connect\(.{0,100}\,\s.{0,100}Process\.start\(\'sh\'\,\s\[\]\).{0,100}socket\.write\(output\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string39 = "Invoke-ConPtyShell " nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string40 = /Invoke\-ConPtyShell\.ps1/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string41 = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwAC4AMQAwACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBu" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string42 = "java/jsp_shell_reverse_tcp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string43 = "java/shell_reverse_tcp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string44 = "linux/x64/meterpreter/reverse_tcp"
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string45 = "linux/x64/shell_reverse_tcp"
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string46 = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"\/bin\/bash\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string47 = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"\/bin\/sh\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string48 = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"bash\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string49 = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"cmd\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string50 = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"powershell\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string51 = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"pwsh\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string52 = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"zsh\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string53 = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'sh\s\-i\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string54 = /lua5\.1\s\-e.{0,100}require\(\\"socket\\"\).{0,100}tcp\:connect.{0,100}io\.popen.{0,100}receive\(\).{0,100}send\(\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string55 = "msfvenom -p " nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string56 = /Net\.Sockets\.TCPClient.{0,100}Net\.Security\.SslStream.{0,100}AuthenticateAsClient.{0,100}Invoke\-Expression.{0,100}Out\-String/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string57 = "Online - Reverse Shell Generator" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string58 = "osx/x64/meterpreter/reverse_tcp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string59 = "osx/x64/meterpreter_reverse_tcp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string60 = "osx/x64/shell_reverse_tcp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string61 = "pentestmonkey/php-reverse-shell" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string62 = /pentestmonkey\@pentestmonkey\.net/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string63 = /perl\s\-e\s\'use\sSocket\;\$.{0,100}\;socket\(S\,PF_INET\,SOCK_STREAM\,getprotobyname/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string64 = /perl\s\-MIO\s\-e\s.{0,100}new\sIO\:\:Socket\:\:INET\(PeerAddr\,\\".{0,100}\:.{0,100}\\"\)\;STDIN\-\>fdopen\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string65 = "PHP Meterpreter Stageless Reverse TCP" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string66 = /php\s\-r\s\'\$s\=socket_create\(AF_INET\,SOCK_STREAM\,SOL_TCP\)\;socket_bind\(\$s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string67 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}\)\;exec\(\\"sh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string68 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}\)\;passthru\(\\"sh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string69 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}\)\;popen\(\\"sh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string70 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}\)\;shell_exec\(\\"sh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string71 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}\)\;system\(\\"sh\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string72 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}proc_open\(\\"sh\\"\,/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string73 = "php/meterpreter_reverse_tcp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string74 = "php/reverse_php" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string75 = /php\-reverse\-shell\.php/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string76 = /python\s\-c.{0,100}\'import\ssocket\,subprocess\,os\'.{0,100}socket\.socket\(socket\.AF_INET.{0,100}connect\(\(\\".{0,100}\)\).{0,100}dup2.{0,100}pty\.spawn\(\\"sh\\"\)\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string77 = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"\/bin\/bash\\"\)/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string78 = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"\/bin\/sh\\"\)/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string79 = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"bash\\"\)/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string80 = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"cmd\\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string81 = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"powershell\\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string82 = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"pwsh\\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string83 = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"sh\\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string84 = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"zsh\\"\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string85 = /python.{0,100}\s\-c\s\'import\sos\,pty\,socket.{0,100}socket\.socket\(\).{0,100}s\.connect\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string86 = /python.{0,100}\s\-c\s\'import\ssocket\,subprocess\,os\;.{0,100}socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\).{0,100}\.connect\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string87 = "python3 -m pwncat -lp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string88 = "python3 -m pwncat -m windows -lp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string89 = "rcat connect -s sh " nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string90 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"\/bin\/bash\\"\s/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string91 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"\/bin\/sh\\"\s/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string92 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"bash\\"\s/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string93 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"cmd\\"\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string94 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"powershell\\"\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string95 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"pwsh\\"\s/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string96 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"zsh\\"\s/ nocase ascii wide
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
        $string100 = /rm\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|sh\s\-i\s2\>\&1\|nc\s.{0,100}\s\>\/tmp\/f/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string101 = /rm\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|sh\s\-i\s2\>\&1\|ncat\s\-u\s.{0,100}\s\>\/tmp\// nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string102 = /ruby\s\-rsocket\s\-e.{0,100}TCPSocket\.new.{0,100}loop.{0,100}gets.{0,100}chomp.{0,100}IO\.popen.{0,100}read/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string103 = /ruby\s\-rsocket\s\-e\'spawn\(\\"\/bin\/bash\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string104 = /ruby\s\-rsocket\s\-e\'spawn\(\\"\/bin\/sh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string105 = /ruby\s\-rsocket\s\-e\'spawn\(\\"bash\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string106 = /ruby\s\-rsocket\s\-e\'spawn\(\\"cmd\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string107 = /ruby\s\-rsocket\s\-e\'spawn\(\\"powershell\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string108 = /ruby\s\-rsocket\s\-e\'spawn\(\\"pwsh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string109 = /ruby\s\-rsocket\s\-e\'spawn\(\\"sh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string110 = /ruby\s\-rsocket\s\-e\'spawn\(\\"zsh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string111 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\s\/bin\/bash\\"/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string112 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\s\/bin\/sh\\"/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string113 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\sbash\\"/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string114 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\scmd\\"/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string115 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\spowershell\\"/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string116 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\spwsh\\"/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string117 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\szsh\\"/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string118 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c.{0,100}\s\/dev\/tcp\/.{0,100}\//
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string119 = /sh\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\>\&1/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string120 = /sh\s\-i\s\>\&\s\/dev\/udp\/.{0,100}\/.{0,100}\s0\>\&1/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string121 = /sh\s\-i\s5\<\>\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\<\&5\s1\>\&5\s2\>\&5/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string122 = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"\/bin\/bash\\"/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string123 = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"\/bin\/sh\\"/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string124 = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"bash\\"/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string125 = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"cmd\\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string126 = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"powershell\\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string127 = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"pwsh\\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string128 = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"zsh\\"/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string129 = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:sh/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string130 = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\'sh/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string131 = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"\/bin\/bash\\"\s\|\snc.{0,100}\'/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string132 = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"\/bin\/sh\\"\s\|\snc.{0,100}\'/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string133 = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"bash\\"\s\|\snc.{0,100}\'/
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string134 = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"cmd\\"\s\|\snc.{0,100}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string135 = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"powershell\\"\s\|\snc.{0,100}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string136 = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"pwsh\\"\s\|\snc.{0,100}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string137 = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"zsh\\"\s\|\snc.{0,100}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string138 = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|sh\s\-i.{0,100}\|nc.{0,100}\'/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string139 = "struct sockaddr_in revsockaddr" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string140 = /stty\sraw\s\-echo\;\s\(stty\ssize\;\scat\)\s\|\snc\s\-lvnp/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string141 = /System\.Net\.Sockets\.TCPClient.{0,100}GetStream\(\).{0,100}iex.{0,100}Out\-String/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string142 = "Windows Bind TCP ShellCode - BOF" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string143 = /Windows\sMeterpreter\sStaged\sReverse\sTCP\s\(x64/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string144 = /Windows\sMeterpreter\sStageless\sReverse\sTCP\s\(x64\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string145 = "Windows Staged JSP Reverse TCP" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string146 = /Windows\sStaged\sReverse\sTCP\s\(x64\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string147 = /Windows\sStageless\sReverse\sTCP\s\(x64\)/ nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string148 = "windows/x64/meterpreter/reverse_tcp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string149 = "windows/x64/meterpreter_reverse_tcp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string150 = "windows/x64/meterpreter_reverse_tcp" nocase ascii wide
        // Description: Reverse Shell Generator
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string151 = "windows/x64/shell_reverse_tcp" nocase ascii wide
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
