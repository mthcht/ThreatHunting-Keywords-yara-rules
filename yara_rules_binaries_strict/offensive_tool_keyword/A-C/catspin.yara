rule catspin
{
    meta:
        description = "Detection patterns for the tool 'catspin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "catspin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string1 = /\scatspin\.sh\s/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string2 = /\sfile\:\/\/catspin\.yaml\s/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string3 = /\s\-\-stack\-name\scatspin\s/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string4 = /\/catspin\.git/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string5 = /\/catspin\-main\// nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string6 = /\/execute\-api\.eu\-central\-1\.amazonaws\.com\/catspin_deployed/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string7 = /\[\+\]\sUse\s\-info\sto\sget\sstack\sstatus\sand\sthe\senpoint\surl\sof\scatspin/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string8 = /\[\+\]\sYou\sspin\smy\sgato\sround\sright\sround\s\?/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string9 = /\\catspin\-main\\/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string10 = /catspin\.sh\shttp/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string11 = /catspin\.sh\s\-info/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string12 = /catspin\.sh\s\-kill/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string13 = /catspin\.sh\s\-run\s/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string14 = /catspin_for_readme\.mp4/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string15 = /catspin_poc\.mp4/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string16 = /catspin_poc_final\.mp4/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string17 = /rootcathacking\/catspin/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string18 = /Spins\sup\scatspin\susing\sApi\sGateway\sproxy/ nocase ascii wide
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
