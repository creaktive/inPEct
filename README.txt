inPEct by Stas
==============

Coded by Stas (Mail: stas@grad.icmc.sc.usp.br; URL: http://sysd.hypermart.net);
(C)opyLeft by SysD Destructive Labs, 1997-2000


	CONTENTS:

I.      What?
II.     Why?
III.    How?
IV.     FAQ
V.      Technical
VI.     Bugs
VII.    Future versions
VIII.   History
IX.     References


=========================
I.      What?
=========================

inPEct is a program that allows you to bind 2 executables in one. So, you
can get some inoffensive joke proggy and insert a bad trojan/worm in it.
When someone executes it, it opens joke program in foreground and a
Bad Thing in background...


=========================
II.     Why?
=========================

"Why do I need to infect my files?" Well... If you are asking a such
question, I think you just got a wrong package... ;)
Now, why to use inPEct and not any similar tool, like Silk Rope 2K?
Here are some advantagies:

i).     inPEct is faster and smaller. See Technical section if you wanna know
        why, here I'll just say that Silk Rope's Loader (program that makes
        2 programs run when only one is executed) has 40960 bytes, and
        inPEct's, about 800 bytes.
ii).    inPEct is more discrete. Sure, being faster/smaller implies that user
        gets less chances to see Strange Things happening in background.
        But inPEct is transparent to user: it does not changes victim
        program's Icon/Version info/Date/Attributes... Only a size!
iii).   inPEct is more paranoid. It's own code, and also trojan's code is
        encrypted, so smart user won't see 2 MZ headers in same executable.
iv).    inPEct is smarter. It will remember if it already had run trojan,
        if it had, it will not do it again... So, trojan will not conflict
        with itself :P

But inPEct also has some things that really pisses me off:

i).     Quite unstable. Some programs that works fine before being binded
        by inPEct becomes boring GPF generators after.
ii).    You can only infect Win32 PE (Portable Executable) files with
        Win 16/32 executables. Attempt to infect non-supported executable
        is refused; attempt to infect with non-supported executable fails.

So, the choice is yours ;)
inPEct is currencly in constant development stage, so it is probable it being
more usefull than similar tools.


=========================
III.    How?
=========================

I expect that GUI is self-explanatory, but anyway, here is terminology:

        o Victim: main program, that appears to user normally.
        o Trojan: bad guy, that is covered by Victim.
        o Output Dir: where generated executable is stored.

Now, select files and click "inPEct" button!!! Have a fun!!! =)

NOTE: Please read FAQ for tricks/tips


=========================
IV.     FAQ
=========================

Q: Why you called it "inPEct"?
A: 'Cos it inserts it's code in PE executables.

Q: When I execute infected executable at first time, it executes both Victim
   and trojan; but at second time, only Victim appears?
A: This is a feature, not a bug (Duh, that smells Microsoft ;)
   Take a look to Why? section.

Q: Why can't I infect Win16/DOS programs?
A: InPEct can only work with PE images, Win16/DOS are quite different and
   less cool to support.

Q: Why can't I insert multiple trojans in single file?
A: Cos' inPect's technique is such uncommon that it doesn't supports itself :P

Q: So, what can I do?
A: Well... At first, infect trojan A with trojan B and infect program C with
   generated file.

Q: When I try to execute infected file, it hangs. Why?
A: InPEct supports a very stricted range of PE features. But I'm expanding it...

Q: InPEct sux! What can I use instead of it?
A: The only program I know is SilkRope, but it doesn't uses real infection.


=========================
V.     Technical
=========================

As you may saw, inPEct's code is free. Use it as you want, just don't forget
to put any reference to me ;)

a). Outside
So, how does inPEct works? Just like any Windoze virus. When analog programs
(as Silk Rope) creates king of self-extractor that extracts/executes 2
programs, inPEct inserts it's code at the end of victim executable, and
dumps Trojan directly from memory. Take a look:

* Silk Rope session
i). User runs JOKE.EXE.
ii). JOKE.EXE copies VICTIM.EXE from it's end to the disk.
iii). JOKE.EXE copies TROJAN.EXE from it's end to the disk.
iv). TROJAN.EXE and VICTIM.EXE are read to memory again and executed.

As you see, it has too many disk reads/writes... This implies in performance
loss and makes user suspect something. And now:

* inPEct session
i). User runs JOKE.EXE.
ii). JOKE.EXE dumps TROJAN.EXE to disk (note that it's already in memory!).
iii). TROJAN.EXE is executed.
iv). JOKE.EXE proceeds execution.

Much less disk accesses, huh?

b). Inside
inPEct uses a quite uncommon technique to insert it's code into executable.
For convenience, I'll call code that makes possible execution of patched
program as "Loader". Generally, Loader has it's own tiny Import Table, that
contains most important KERNEL32 APIs: LoadLibrary and GetProcAddress. When
Windows loads patched program, it resolves small Loader's Import Table. Now,
Loader itself loads the rest of original Import Table, runs it's code and
passes control to original code.
With inPEct is such different and simplier: original Import Table is patched,
so Loader just executes it's own and soon original code. So, why do nobody
uses such technique? Answer is really dumb: "What do we cut from Loader, we
may put in Infector". So, in inPEct's case, Infector code is a burning hell...
Personally, I saw only one program that uses a such technique: inPEct itself ;)


=========================
VI.     Bugs
=========================

*LOTS* of bugs :(
Currently, I fixed the most I know, but there remains:

	o Console Trojan programs used to fail in WinNT/2K enviroment.
	o DOS programs used to fail everywhere.
	o New Bound Import style is quite uncomplete.
	o Some Infector code is, ghmmm, stupid. I had no patience to do it right.


=========================
VII.    Future versions
=========================

Future versions may have:
	o Bug fixes (sure!).
	o Code enhancements (if I got some free time).
	o Clearer, commented source (hey, do you want to comment it for me? ;)
	o Infection algorythm expansions (hell, didn't you liked current one?)
	o Bind multiple (more than 2) executables and/or execute'em directly
          from memory, with no disk accesses at all (*ONLY ON REQUEST* And give
          me a good reason to do that).


=========================
VIII.   History
=========================

* InPEct v1.0
	First public release.


=========================
IX.     References
=========================

* Most of loader and some of infector code from PeSentry 0.05a by Kill3xx.
* Started it all from simple PE crypter Beta 3 by hayras.
* Took a look to PE Rebuilder v0.95b by Titi & Virogen.
* Few lines from Net Walker! File Fat Remover.

I also used:
* CD-ROM Eject/Close Sample Program by Dolphinz©.
* Iczelion tutorials.
* "The PE file format" doc by unknown

...And many others. I would also thank all alpha/beta testers; t0p, MiCKeY
and Wagner Patriota G. Soares.