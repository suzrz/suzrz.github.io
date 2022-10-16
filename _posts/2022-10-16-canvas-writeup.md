# Canvas CTF

This challenge is from [hackthebox](www.hackthebox.com). It is ranked as easy and is for 10pts at the time of writing this writeup.

For me this is first encouter with JavaScript based challenges, but I am interested in JavaScript analysis as it is widely used.

## Initial Analysis

The archive contains two html files and two directories. The most interesting is `js/` folder with `login.js` file. 

### JS Script Analysis

The js file is obviously obfuscated. I've used online deobfuscator and obtained readable code. 

The interesting line is at the end of the file. 

By executing the last line and printing the result I've obtained the flag :)

![](/assets/canvas/flag.png)


## Conclusion

This challenge was actually pretty easy. I am glad that I've had the opportunity to encouter the js obfuscation and solve this challenge.

