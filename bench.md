# ANTES DO PACKET WORKER EM C ->

rsha@rsha-pwned ~/Documents/workspace/REEcanner $ sudo python3 main.py -r 0 -w 16 -q
[*] reecanner initialized. targeting 1 ports.
[*] workers: 16 | rate: 0 pps | seed: 2018542222

[*] sent: 3.080.192 | rate: 227.588 pps | found: 388 | next index: 3080192

scan stats
  time elapsed: 13.85s
  hosts found:  388

rsha@rsha-pwned ~/Documents/workspace/REEcanner $ ^C

rsha@rsha-pwned ~/Documents/workspace/REEcanner $ sudo pypy3 main.py -r 0 -w 16 -q
[*] reecanner initialized. targeting 1 ports.
[*] workers: 16 | rate: 0 pps | seed: 2595064299

[*] sent: 10.002.432 | rate: 652.267 pps | found: 513 | next index: 10002432

scan stats
  time elapsed: 15.47s
  hosts found:  513

rsha@rsha-pwned ~/Documents/workspace/REEcanner $ ^C

# DEPOIS DO PACKET WORKER EM C ->
