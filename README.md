# ZombieThread
Another meterpreter injection technique using C# that attempts to bypass WD.

# Introduction
The idea behind this project was to try to figure out how inject shellcode into a remote process and go under the Windows Defender's radar.

The technique is quite simple:

- Open a remote process using `OpenProcess`.
- Decrypt the meterpreter payload in memory.
- Allocate some memory in the remote process using `VirtualAllocEx`, ensuring we assign the correct permissions to write to the memory of course.
- Write our payload into the allocated memory using `WriteProcessMemory`.
- Protect the memory using `VirtualProtectEx`, setting the protection to `PAGE_NOACCESS`.
- Create a new suspended thread using `CreateRemoteThread`.
- Sleep for 10 seconds while Defender scans the remote process memory for malicious code.
- Change the protection on the memory using `VirtualProtectEx`, setting the protection to `PAGE_EXECUTE_READ_WRITE`.
- Resuming the remote thread using `ResumeThread`

It would appear that protecting the page with `PAGE_NOACCESS` containing our meterpreter shellcode is not scanned by Defender and is not detected. By suspending the thread upon creation we are able to 'hold' the shellcode in memory until Defender has done it's scan then execute the shellcode when Defender has finished.

# Proof-of-Concept

![AV Scan](https://github.com/Bl4ckM1rror/ZombieThread/blob/main/PoC.png?raw=true)

# Important
Remember, the code looks for an instance of explorer to inject into, if you want inject into another process, you must change it in program.cs code.

# AV Scan Results

![AV Scan](https://github.com/Bl4ckM1rror/ZombieThread/blob/main/antiscan.png?raw=true)
