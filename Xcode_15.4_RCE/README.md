Steps to reproduce:

1. Create 3 GitHub repositories: "fin", "dep" and "poc".
2. Execute the script with `% ./exploit.sh` 
3. Open Xcode (version 15.4) and clone the "poc" repository.

Despite knowing that the root cause of this bug was public ([CVE-2024-32002](https://github.com/safebuffer/CVE-2024-32002)),
 I decided to have a try and I reported this to Apple with their BB program.
After keeping the report opened for about 3 weeks claiming they were reviewing it,
 they closed it because "unable to identify a security issue".
Finally, I noted that with the upcoming Xcode release (16.0) they fixed this issue.
