
As we've previously highlighted, adhering to the sequence of data volatility is crucial. It's imperative that we scrutinize each byte to detect the subtle traces left by cyber adversaries. Having covered memory forensics, let's now shift our attention to the area of `disk forensics` (disk image examination and analysis).

Many disk forensic tools, both commercial and open-source, come packed with features. However, for incident response teams, certain functionalities stand out:

- `File Structure Insight`: Being able to navigate and see the disk's file hierarchy is crucial. Top-tier forensic tools should display this structure, allowing quick access to specific files, especially in known locations on a suspect system.
- `Hex Viewer`: For those moments when you need to get up close and personal with your data, viewing files in hexadecimal is essential. This capability is especially handy when dealing with threats like tailored malware or unique exploits.
- `Web Artifacts Analysis`: With so much user data tied to web activities, a forensic tool must efficiently sift through and present this data. It's a game-changer when you're piecing together events leading up to a user landing on a malicious website.
- `Email Carving`: Sometimes, the trail leads to internal threats. Maybe it's a rogue employee or just someone who slipped up. In such cases, emails often hold the key. A tool that can extract and present this data streamlines the process, making it easier to connect the dots.
- `Image Viewer`: At times, the images stored on systems can tell a story of their own. Whether it's for policy checks or deeper dives, having a built-in viewer is a boon.
- `Metadata Analysis`: Details like file creation timestamps, hashes, and disk location can be invaluable. Consider a scenario where you're trying to match the launch time of an app with a malware alert. Such correlations can be the linchpin in your investigation.

Enter [Autopsy](https://www.autopsy.com/): a user-friendly forensic platform built atop the open-source Sleuth Kit toolset. It mirrors many features you'd find in its commercial counterparts: timeline assessments, keyword hunts, web and email artifact retrievals, and the ability to sift results based on known malicious file hashes.

Once you've loaded a forensic image and processed the data, you'll see the forensic artifacts neatly organized on the side panel. From here, you can:

![Autopsy interface showing data sources and artifacts, including file views, data artifacts like Chromium extensions, and analysis results with keyword hits.](https://academy.hackthebox.com/storage/modules/237/image16.png)

- Dive into `Data Sources` to explore files and directories. ![File explorer showing data sources with folders: OrphanFiles, CarvedFiles, Extend, Recycle.Bin, $Unalloc, Config.Msi, Documents and Settings, PerfLogs, Program Files, Program Files (x86), ProgramData, Recovery, System Volume Information, Tools, Users, Windows.](https://academy.hackthebox.com/storage/modules/237/image1_.png)
    
- Examine `Web Artifacts`. ![Autopsy interface showing data artifacts with a focus on 'Web Cache', listing URLs, domains, and creation dates from a keyword search for 'powershell.exe'.](https://academy.hackthebox.com/storage/modules/237/image80.png)
    
- Check `Attached Devices`. ![Autopsy interface showing 'USB Device Attached' data artifacts, listing device make, model, ID, and timestamps for attached devices.](https://academy.hackthebox.com/storage/modules/237/image8_.png)
    
- Recover `Deleted Files`. ![Autopsy interface showing data sources and deleted files listing, with file names, modified times, and locations from a keyword search for 'powershell.exe'.](https://academy.hackthebox.com/storage/modules/237/image51.png)
    
- Conduct `Keyword Searches`. ![Autopsy interface showing data sources and a keyword search for 'powershell.exe' with substring match selected, listing 'fulldisk.raw.001' as the data source.](https://academy.hackthebox.com/storage/modules/237/image75.png)
    
    ![Autopsy interface showing a keyword search for 'powershell.exe', listing files like Windows PowerShell.lnk, NTUSER.DAT.LOG1, $LogFile, with locations and modified times.](https://academy.hackthebox.com/storage/modules/237/image23.png)
    
- Use `Keyword Lists` for targeted searches. ![Autopsy interface showing keyword lists with options for Phone Numbers, IP Addresses, Email Addresses, URLs, and Credit Card Numbers, with 'fulldisk.raw.001' as the data source.](https://academy.hackthebox.com/storage/modules/237/image72.png)
    
    ![Autopsy interface showing keyword search results for 'powershell.exe', listing files like f0150936.dll and f0250748.dll, with locations and IP address details highlighted.](https://academy.hackthebox.com/storage/modules/237/image52.png)
    
- Undertake `Timeline Analysis` to map out events. ![Timeline Editor showing events for applications like Notepad++, WinRAR, Process Hacker, and Google Chrome, with visual counts and details from August 10, 2023.](https://academy.hackthebox.com/storage/modules/237/image99.png)
    

---

We'll be heavily utilizing Autopsy in the forthcoming "Practical Digital Forensics Scenario" section.