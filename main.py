import logging
import os
from logging.handlers import RotatingFileHandler

import discord
from dotenv import load_dotenv

from VirusTotalHandler import VirusTotalHandler

load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
VIRUSTOTAL_APIKEY = os.getenv("VIRUSTOTAL_APIKEY")
GUILD_ID = os.getenv("GUILD_ID")


# Setup Logging ####
logger = logging.getLogger("VirusChecki-BOT")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(fmt="%(asctime)s %(levelname)-8s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
ch = logging.StreamHandler()
fh = RotatingFileHandler("fastapi.log", maxBytes=10000000, backupCount=3)
ch.setFormatter(formatter)
fh.setFormatter(formatter)
logger.addHandler(ch)
logger.addHandler(fh)


intents = discord.Intents.default()
intents.message_content = True
bot = discord.Bot(intents=intents)

virus_total_handler = VirusTotalHandler(logger, VIRUSTOTAL_APIKEY)


@bot.slash_command()
async def hello(ctx, name: str = None):
    name = name or ctx.author.name
    await ctx.respond(f"Hello {name}!")


@bot.slash_command(name="help", description="Show help message and description", guild_ids=[GUILD_ID])
async def help_command(ctx: discord.ApplicationContext):
    embed = discord.Embed(title="VirusChecki-BOT", description="A Discord bot to check for malicious files")
    fields = [
        {
            "name": "About",
            "value": "This bot uses the [VirusTotal-API](https://www.virustotal.com/) to check all files for malicious content.\nThe code is open-source and publicly available on [Github](https://github.com/bananensplit/).",
        },
        {
            "name": "How does it work?",
            "value": "For every message with attached files the bot will try to generate a scan of each file. The bot sends each attached file to the [VirusTotal-API](https://www.virustotal.com/) and waits for a result. VirusTotal checks the file against a number of antivirus engins and then returns the output of each of them. The summary of this output will then be send as a reply to the original message.\n\n",
        },
        {
            "name": "How to read output?",
            "value": "For each file there will be five fields shown (descriptions below). These represent the 'threatlevels' the antivirus engines assigned to the file. The number on the right to the threatlevel shows the total count of engines that assigned this specific threatlevel.\n\n- `malicious` : The file is infected and you should not download it!\n- `suspicious` : Is not malicious by itself but it can be used in a malicious way.\n- `harmless` : The file is harmless and safe to download.\n- `undetected` : Same as `harmless`.\n- `timeout` : Didn't get a response from the antivirus engine in time.",
        },
        {
            "name": "When is a file a virus?",
            "value": "One or two `malicious` categorizations are usually false positives. But going up the chance of a virus increases drasticly. I presonally would be carefull with three and when four engines think this file is `malicious` i would consider it infected and not download it.",
        },
    ]
    for field in fields:
        embed.add_field(name=field["name"], value=field["value"], inline=False)
        embed.add_field(name="\u200b", value="", inline=False)

    embed.set_footer(text="Made with ❤️ by bananensplit on Github.\nPowered by VirusTotal.")
    await ctx.respond(embed=embed)


@bot.event
async def on_message(message: discord.message.Message):
    print(type(message))
    if message.author == bot.user:
        return

    logger.info(f"Message from {message.author}: {message.content}")

    if len(message.attachments) > 0:
        logger.info(f"Attachment detected: {message.attachments[0].url}")

        async with message.channel.typing():
            embed = discord.Embed(title="Scan Result")
            embed.set_footer(text="Made with ❤️ by bananensplit on Github.\nPowered by VirusTotal.")

            for attachment in message.attachments:
                result = await virus_total_handler.scan_url(message.attachments[0].url)
                attachment_stats = result["data"]["attributes"]["stats"]

                categories = ["malicious", "suspicious", "harmless", "undetected", "timeout"]
                field_value = [f"{attachment_stats[category]} {category}\n" for category in categories]
                field_value = "".join(field_value)
                embed.add_field(name=f"Result for '{attachment.filename}'", value=field_value, inline=False)

            await message.reply(embed=embed)


@bot.event
async def on_ready():
    logger.info(f"Logged in as {bot.user.name} - {bot.user.id}")


bot.run(DISCORD_TOKEN)
