Using:

```python
from PromodeQuerier import PromodeQuerier
import asyncio

# async method
async def main():
	servers = await PromodeQuerier.queryMasterAsync("master.ioquake3.org",27950,5)
	print(await PromodeQuerier.queryServersAsync(servers,5))
	print(await PromodeQuerier.queryServerAsync("isona.me",27960,5))
asyncio.run(main())

# sync method
servers = [["138.2.130.215",27960], ["master.maverickservers.com", 27950], ["master3.idsoftware.com", 27950],["51.38.83.66", 27960], ["51.38.83.66", 27961], ["games.magnoren.uk", 27960], ["snapcase.net", 27960], ["cpma.ovh", 27960], ["cpma.ovh", 27961], ["newtype.eu", 27961], ["newtype.eu", 27962], ["q3df.ru", 27970], ["q3df.ru", 27971], ["q3df.ru", 27972], ["isona.me", 27960], ["oafps.com", 27961], ["oafps.com", 27962], ["oafps.com", 27963], ["oafps.com", 27964], ["snapcase.net", 27961], ["artemis.snapcase.net", 27960], ["artemis.snapcase.net", 27961], ["46.38.48.64", 27960], ["46.38.48.64", 27961], ["46.38.48.64", 27962]]

print(PromodeQuerier.queryServers(servers,4))
print(PromodeQuerier.queryServer("isona.me",27960,5))

```