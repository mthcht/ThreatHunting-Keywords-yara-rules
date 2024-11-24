rule demiguise
{
    meta:
        description = "Detection patterns for the tool 'demiguise' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "demiguise"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string1 = /\sdemiguise\.py/ nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string2 = /\s\-k\s.{0,100}\s\-c\s.{0,100}\.exe.{0,100}\s\-p\sOutlook\.Application\s\-o\s.{0,100}\.hta/ nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string3 = /\s\-k\s.{0,100}\s\-c\s.{0,100}cmd\.exe\s\/c\s.{0,100}\s\-o\s.{0,100}\.hta\s\-p\sShellBrowserWindow/ nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string4 = /\/demiguise\.py/ nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string5 = /\\demiguise\.py/ nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string6 = "nccgroup/demiguise" nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string7 = /Yh0Js82rIfFEbS6pR7oUkN0Use54pIZBa3fpYprAMuURNrZZGc6cM8dc\+AC/ nocase ascii wide
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
