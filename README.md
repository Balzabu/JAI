```
       #    #    ### 
       #   # #    #   
       #  #   #   #   
       # #     #  #    
 #     # #######  #    Just Another (DLL) Injector
 #     # #     #  #    Made by Balzabu
  #####  #     # ###   https://github.com/Balzabu
```
![C++](https://img.shields.io/badge/Made_with-C++-blue)[![Follow](https://img.shields.io/badge/Follow_me-github-black?logo=github)](https://github.com/balzabu/)


## What is DLL Injection?

DLL Injection is a technique that allows users to run any code in the memory of another process by forcing it to load a foreign DLL file.
It can be used for many purposes including hooking system functions, malware attacks and game hacking.

## What is JAI?

JAI is my own C++ implementation of a DLL Injector using the LoadLibrary method, it is able to inject any DLL you pass to it into any visible process on x86/x64.

## Can I use this to inject modern games?

Yes, as long as the game doesn't use any kind of Anti-Cheat engine you will be able to inject DLLs into its processes through JAI.
Please, don't even consider trying to defeat engines such as EAC or BattlEye using JAI; you won't have success and will likely get your account banned.

## Visual Studio

Simply open the Solution file (.sln) and build Release or Debug, I've tried to comment as much code as possible since it helped me understand everything better.

Windows SDK is probably a requirement, but I assume you already have it installed.

## Releases

If you don't want to build the project by yourself, you can download one of the releases available.

Remember that they will only work on machines running Windows XP or higher.

## Demo

![](https://i.ibb.co/D82t0r7/JAI-GIF.gif)
