rule frp
{
    meta:
        description = "Detection patterns for the tool 'frp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "frp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string1 = /\/frp\.git/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string2 = /\/frp_0\..{0,1000}\..{0,1000}_darwin_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string3 = /\/frp_0\..{0,1000}\..{0,1000}_darwin_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string4 = /\/frp_0\..{0,1000}\..{0,1000}_freebsd_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string5 = /\/frp_0\..{0,1000}\..{0,1000}_linux_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string6 = /\/frp_0\..{0,1000}\..{0,1000}_linux_arm\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string7 = /\/frp_0\..{0,1000}\..{0,1000}_linux_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string8 = /\/frp_0\..{0,1000}\..{0,1000}_linux_mips\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string9 = /\/frp_0\..{0,1000}\..{0,1000}_linux_mips64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string10 = /\/frp_0\..{0,1000}\..{0,1000}_linux_mips64le\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string11 = /\/frp_0\..{0,1000}\..{0,1000}_linux_mipsle\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string12 = /\\frp_0\..{0,1000}\..{0,1000}_darwin_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string13 = /\\frp_0\..{0,1000}\..{0,1000}_darwin_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string14 = /\\frp_0\..{0,1000}\..{0,1000}_freebsd_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string15 = /\\frp_0\..{0,1000}\..{0,1000}_linux_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string16 = /\\frp_0\..{0,1000}\..{0,1000}_linux_arm\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string17 = /\\frp_0\..{0,1000}\..{0,1000}_linux_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string18 = /\\frp_0\..{0,1000}\..{0,1000}_linux_mips\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string19 = /\\frp_0\..{0,1000}\..{0,1000}_linux_mips64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string20 = /\\frp_0\..{0,1000}\..{0,1000}_linux_mips64le\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string21 = /\\frp_0\..{0,1000}\..{0,1000}_linux_mipsle\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string22 = /fatedier\/frp/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string23 = /frpc\s\-c\s.{0,1000}frpc\.ini/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string24 = /frpc\sreload\s\-c\s/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string25 = /frpc\sstatus\s\-c\s/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string26 = /frpc\sverify\s\-c\s/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string27 = /frpc_windows_amd64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string28 = /frpc_windows_arm64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string29 = /frps\s\-c\s.{0,1000}frps\.toml/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string30 = /frps_windows_amd64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string31 = /frps_windows_arm64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string32 = /ssh\s\-o\s\'proxycommand\ssocat\s\-\s/ nocase ascii wide

    condition:
        any of them
}
