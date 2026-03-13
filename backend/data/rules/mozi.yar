/*
    Mozi P2P Botnet YARA Rules — v4 FINAL
    Written from actual string extraction of sample:
    22ea54360f7b59f926660f70b05b11f6b00bc1519b5114df06176d0c53003e24
    ELF 32-bit MIPS BE, UPX-packed with corrupted header (anti-unpack)
*/

rule Mozi_Packed_MIPS_ELF {
    meta:
        description  = "Detects Mozi botnet UPX-packed MIPS ELF — matches confirmed sample strings"
        family       = "Mozi"
        type         = "P2P Botnet"
        threat_actor = "Chinese threat actor (arrested 2021, botnet persists)"
        mitre_attack = "T1027, T1498, T1071.001, T1190"
        severity     = "HIGH"
        reference    = "https://blog.netlab.360.com/mozi-another-botnet-using-dht/"

    strings:
        // Mozi self-update URL format string — unique to Mozi
        $mozi_url    = "p://%s:%d/Mo" ascii

        // Baidu connectivity check — Mozi pings Baidu to verify internet access
        $baidu       = "+://baidu" ascii

        // C2 beacon HTTP fragment
        $c2_beacon   = "mes/ HTTP/1.1" ascii

        // Router exploits Mozi uses for spreading
        $exploit1    = "POST /GponForm/diag_" ascii   // GPON ONT exploit CVE-2018-10561
        $exploit2    = "HNAP1/" ascii                  // D-Link HNAP exploit
        $exploit3    = "Host: 127.0" ascii             // UPnP localhost exploit

        // Shell injection marker
        $shell       = "${IFS}" ascii

        // UPX packer markers
        $upx1        = "UPX!" ascii
        $upx2        = "This file is packed with the UPX" ascii

        // Self-replication
        $selfexe     = "/proc/self/exe" ascii

        // HTTP keep-alive pattern in C2 comms
        $keepalive   = "keep-alive" ascii

        // MIPS 32-bit Big Endian ELF magic: 7f 45 4c 46 01 02 01
        $elf_mips_be = { 7F 45 4C 46 01 02 01 00 }

    condition:
        $elf_mips_be at 0
        and filesize > 50KB
        and filesize < 600KB
        and $upx1
        and (
            $mozi_url
            or ($baidu and $c2_beacon)
            or ($exploit1 and $exploit2)
            or ($mozi_url and $selfexe)
        )
}

rule Mozi_Router_Exploit_Strings {
    meta:
        description = "Detects Mozi router exploitation strings in packed ELF"
        family      = "Mozi"
        type        = "P2P Botnet"
        severity    = "HIGH"

    strings:
        $g1 = "POST /GponForm/diag_" ascii
        $g2 = "mes/ HTTP/1.1" ascii
        $g3 = "Host: 127.0" ascii
        $g4 = "keep-alive" ascii
        $g5 = "gzip, deflat" ascii
        $g6 = "HNAP1/" ascii
        $g7 = "p://%s:%d/Mo" ascii
        $g8 = "${IFS}" ascii
        $g9 = "DEATH" ascii

    condition:
        uint32(0) == 0x464C457F
        and 4 of them
}

rule Mozi_Connectivity_Check {
    meta:
        description = "Detects Mozi Baidu connectivity check + update URL"
        family      = "Mozi"
        type        = "P2P Botnet"
        severity    = "HIGH"

    strings:
        $b1 = "+://baidu" ascii
        $b2 = "p://%s:%d/Mo" ascii
        $b3 = "UPX!" ascii

    condition:
        uint32(0) == 0x464C457F
        and all of them
}

rule Mozi_DHT_Fragment {
    meta:
        description = "Detects Mozi partial DHT bencoding fragment"
        family      = "Mozi"
        type        = "P2P Botnet"
        severity    = "MEDIUM"

    strings:
        // Partial DHT bencoded string visible in packed binary
        $dht1 = "ad2:id2" ascii      // fragment of "d1:ad2:id20:"
        $dht2 = "p://%s:%d/Mo" ascii
        $dht3 = "+://baidu" ascii

    condition:
        uint32(0) == 0x464C457F
        and 2 of them
}
