
[Unpac.Me](https://unpac.me/) is tool tailored for malware unpacking. The great thing about `Unpac.Me` is that it grants us the capability to run our YARA rules over their amassed database of malware submissions. Considering the hurdles of gaining access to commercialized malware datasets, Unpac.Me emerges as a prime asset for those dedicated SOC analysts and persistent malware enthusiasts.

## Hunting for Evil Within Online Datasets with YARA

Suppose we want to test out the following YARA rule.

Code: yara

```yara
rule ransomware_dharma {

    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from Dharma ransomware"
        reference = "https://www.virustotal.com/gui/file/bff6a1000a86f8edf3673d576786ec75b80bed0c458a8ca0bd52d12b74099071/behavior" 
    
    strings:
        $string_pdb = {  433A5C6372797369735C52656C656173655C5044425C7061796C6F61642E706462 }
	$string_ssss = { 73 73 73 73 73 62 73 73 73 }

        condition: all of them
}
```

So, how do we get started?

- Register for zero-cost access and hop into the platform.
    
- Head over to `Yara Hunt` and choose `New Hunt`. ![UnpacMe interface showing 'Yara Hunt' menu with options for 'New Hunt' and 'History'.](https://academy.hackthebox.com/storage/modules/234/unpac1.png)
    
- Enter the YARA rule into the designated rule space. ![UnpacMe Yara Hunt interface displaying a YARA rule for detecting Dharma ransomware, authored by Madhukar Raina, with specific strings and conditions.](https://academy.hackthebox.com/storage/modules/234/unpac33.png)
    
- First hit `Validate` and then `Scan`. ![Interface showing options for Scan Assist, Fast Scan, Store Offsets, File Size Limits, Validate, Scan, and Total Recall.](https://academy.hackthebox.com/storage/modules/234/unpac44.png)
    
- Scan results get displayed right in front of our eyes. Taking a quick glance at our example, the system hustled through all malware submissions in a couple of minutes, spotting 1 match.
    
    ![Hunt Results showing ransomware_dharma rule with 1 unpacked malware match. Status: complete. Rule validation passed. Scan coverage: 100%. Observed lifespan: 3 years. First seen: 21/02/2020. Last seen: 13/06/2023. File type: EXE, size: 95 KB.](https://academy.hackthebox.com/storage/modules/234/unpac55.png)
    

For individuals and organizations with limited resources, Unpac.Me and similar platforms can serve as stepping stones to enhance their malware analysis and detection capabilities, enabling them to make meaningful contributions to the field of cybersecurity.