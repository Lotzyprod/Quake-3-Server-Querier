from PromodeQuerier import PromodeQuerier
import asyncio

# async method
async def main():
	servers = PromodeQuerier.queryMaster("master.ioquake3.org",27950,5)
	print(await PromodeQuerier.queryMultAsync(servers,10))
	print(await PromodeQuerier.queryAsync("isona.me",27960,5))
asyncio.run(main())
# sync method
servers = [{"address":"138.2.130.215", "port":27960}, {"address":"master.maverickservers.com", "port":27950}, {"address":"master3.idsoftware.com", "port":27950},{"address":"51.38.83.66", "port":27960}, {"address":"51.38.83.66", "port":27961}, {"address":"games.magnoren.uk", "port":27960}, {"address":"snapcase.net", "port":27960}, {"address":"cpma.ovh", "port":27960}, {"address":"cpma.ovh", "port":27961}, {"address":"newtype.eu", "port":27961}, {"address":"newtype.eu", "port":27962}, {"address":"q3df.ru", "port":27970}, {"address":"q3df.ru", "port":27971}, {"address":"q3df.ru", "port":27972}, {"address":"isona.me", "port":27960}, {"address":"oafps.com", "port":27961}, {"address":"oafps.com", "port":27962}, {"address":"oafps.com", "port":27963}, {"address":"oafps.com", "port":27964}, {"address":"snapcase.net", "port":27961}, {"address":"artemis.snapcase.net", "port":27960}, {"address":"artemis.snapcase.net", "port":27961}, {"address":"46.38.48.64", "port":27960}, {"address":"46.38.48.64", "port":27961}, {"address":"46.38.48.64", "port":27962}]

print(PromodeQuerier.queryMult(servers,2))
print(PromodeQuerier.query("isona.me",27960,5))