DETECTIONS = {
    "bruteforce": r"""
index=botsv2 sourcetype=wineventlog:security EventCode=4625
| stats count values(host) as hosts by Account_Name, Source_Network_Address
| where count >= 10
| sort - count
| head 200
""",

    "powershell": r"""
index=botsv2 sourcetype=wineventlog:security EventCode=4688 powershell
| eval cmd=coalesce(Process_Command_Line, CommandLine, process)
| where isnotnull(cmd)
| eval has_suspicious=if(match(lower(cmd),"(-enc|encodedcommand|iex|downloadstring|invoke-webrequest|frombase64string)"),1,0)
| where has_suspicious=1
| eval Process_Command_Line="[REDACTED]"
| table host Account_Name New_Process_Name Parent_Process_Name Process_Command_Line
| head 200
""",

    "lateral": r"""
index=botsv2 sourcetype=wineventlog:security EventCode=4624 Logon_Type=3
| bucket _time span=1h
| stats dc(host) as host_count values(host) as hosts count as event_count by Account_Name, Source_Network_Address, _time
| where host_count >= 5
| sort - host_count - event_count
| head 200
""",
}