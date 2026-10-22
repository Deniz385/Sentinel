/*
 * Sentinel YARA rules
 *
 * In v3.0 this file sat in the repository but no code ever read it.
 * It is now compiled and run by `sentinel/yara_engine.py`
 * (when yara-python is installed: pip install 'sentinel-dlp[yara]').
 *
 * The `meta.severity` field must be one of Sentinel's severity
 * levels: info | low | medium | high | critical
 */

rule Sentinel_EICAR_Test_File
{
    meta:
        description = "EICAR standard antivirus test file"
        severity = "medium"
        author = "Sentinel DLP"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        // The string is assembled in pieces; otherwise this rule file
        // would itself be quarantined by antivirus software.
        $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $a
}

rule Sentinel_Credential_Dump
{
    meta:
        description = "Credential dump pattern"
        severity = "critical"
        author = "Sentinel DLP"

    strings:
        $shadow = /root:[\$!*][^\n:]{0,200}:\d{5}:/
        $sam    = "SAM\\Domains\\Account\\Users" nocase
        $ntlm   = /[a-f0-9]{32}:[a-f0-9]{32}/
        $mimi   = "sekurlsa::logonpasswords" nocase

    condition:
        any of them
}

rule Sentinel_Private_Key_Block
{
    meta:
        description = "Private key block"
        severity = "critical"
        author = "Sentinel DLP"

    strings:
        $rsa     = "-----BEGIN RSA PRIVATE KEY-----"
        $ec      = "-----BEGIN EC PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $pgp     = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        $pkcs8   = "-----BEGIN PRIVATE KEY-----"

    condition:
        any of them
}

rule Sentinel_Webshell_Indicator
{
    meta:
        description = "Webshell indicator: executing commands from user input"
        severity = "high"
        author = "Sentinel DLP"

    strings:
        $php_eval   = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $php_system = /(system|exec|passthru|shell_exec|popen)\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $asp_eval   = /eval\s*\(\s*Request/ nocase
        $py_exec    = /exec\s*\(\s*request\./ nocase

    condition:
        any of them
}

rule Sentinel_Database_Dump
{
    meta:
        description = "Database dump - table structure and bulk INSERT"
        severity = "high"
        author = "Sentinel DLP"

    strings:
        $mysqldump = "-- MySQL dump" nocase
        $pgdump    = "-- PostgreSQL database dump" nocase
        // The Turkish table names below are detection data: this rule
        // targets dumps from Turkish systems as much as English ones.
        $create    = /CREATE TABLE `?(users?|customers?|musteri|kullanici|members?)`?/ nocase
        $insert    = /INSERT INTO `?(users?|customers?|musteri|kullanici)`?/ nocase

    condition:
        ($mysqldump or $pgdump) or (#create > 0 and #insert > 2)
}

rule Sentinel_Exfiltration_Script
{
    meta:
        description = "Exfiltration script: reading files and posting them to a remote address"
        severity = "high"
        author = "Sentinel DLP"

    strings:
        $curl_post  = /curl\s+(-[A-Za-z]+\s+)*(-X\s*POST|--data|-d\s+@)/ nocase
        $requests   = "requests.post(" nocase
        $read_doc   = /(Documents|Belgeler|Desktop|Masa.st|\.ssh|\.aws)/ nocase
        $archive    = /(zipfile|tarfile|7z|rar)\s*[\.\(]/ nocase

    condition:
        ($curl_post or $requests) and $read_doc and $archive
}
