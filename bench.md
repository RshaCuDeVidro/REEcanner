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
rsha@rsha-pwned ~/Documents/workspace/REEcanner $ sudo pypy3 main.py 0.0.0.0/0 -r 0 --batch-size 8192 --override-safety -q
[*] reecanner initialized. targeting 1 ports.
[*] workers: 4 | rate: 0 pps | seed: 3901754091
[*] using C worker (worker.so)

[*] sent: 12.657.664 | rate: 1.196.635 pps | found: 590 | next index: 12657664

scan stats
  time elapsed: 10.61s
  hosts found:  590

rsha@rsha-pwned ~/Documents/workspace/REEcanner $ sudo python3 main.py 0.0.0.0/0 -r 0 --batch-size 8192 --override-safety -q
[*] reecanner initialized. targeting 1 ports.
[*] workers: 4 | rate: 0 pps | seed: 3848841034
[*] using C worker (worker.so)

[*] sent: 23.261.184 | rate: 1.075.453 pps | found: 1101 | next index: 23261184

scan stats
  time elapsed: 21.86s
  hosts found:  1101
