Using:

```python
from PromodeQuerier import PromodeQuerier
import asyncio

# async method
async def main():
	servers = await PromodeQuerier.queryMasterAsync("master.ioquake3.org",27950,5)
	print(await PromodeQuerier.queryServerAsync("isona.me",27960,5))
asyncio.run(main())

# sync method
servers = await PromodeQuerier.queryMaster("master.ioquake3.org",27950,5)
print(PromodeQuerier.queryServer("isona.me",27960,5))

```