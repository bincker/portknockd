To use, compile the code with:

```
$ gcc -o portknockd portknockd.c
```

Then, simply run it as root on the victim machine. Be sure to edit the knock_sequence variable before running. These will be the ports that must be hit before the shell is activated. Once you do that, put the same knock sequence in port\_knock.py with the last port being the port you want the shell spawned back on. Then simply run the python script to spawn a shell on the remote box.

This project is released under the GNU GPLv3 and I am not responsible for any damage caused using this tool.

http://blackhatlibrary.net/

jtripper (c)2013
