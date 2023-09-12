FROM python:3.10
WORKDIR /usr/src/app

# ENV VARIABLES
ENV DISCORD_TOKEN=""
ENV VIRUSTOTAL_APIKEY=""
ENV GUILD_ID=""

# COPY FILES
COPY main.py VirusTotalHandler.py requirements.txt ./

# INSTALL REQUIREMENTS
RUN pip install --no-cache-dir -r requirements.txt

# Create .env file
RUN touch .env &&\
    echo "DISCORD_TOKEN=\"${DISCORD_TOKEN}\"" >> .env &&\
    echo "VIRUSTOTAL_APIKEY=\"${VIRUSTOTAL_APIKEY}\"" >> .env &&\
    echo "GUILD_ID=\"${GUILD_ID}\"" >> .env

# RUN THE APP
CMD ["python", "./main.py"]