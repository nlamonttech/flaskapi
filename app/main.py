#!/usr/bin/env python3.12
# -*- coding: utf-8 -*-

import os
import boto3

from flask import Flask, jsonify, request

app = Flask(__name__)

client = boto3.client('dynamodb', region_name='eu-west-2')

dynamodbTableName = 'sometable' #maybe this should come in as an environment variable?

songs_data = [
    {
        'Artist': 'The Beatles',
        'SongTitle': 'Hey Jude',
        'AlbumTitle': 'The Beatles Again',
        'Year': 1968
    },
    {
        'Artist': 'Led Zeppelin',
        'SongTitle': 'Stairway to Heaven',
        'AlbumTitle': 'Led Zeppelin IV',
        'Year': 1971
    },
    {
        'Artist': 'Pink Floyd',
        'SongTitle': 'Comfortably Numb',
        'AlbumTitle': 'The Wall',
        'Year': 1979
    },
    {
        'Artist': 'Queen',
        'SongTitle': 'Bohemian Rhapsody',
        'AlbumTitle': 'A Night at the Opera',
        'Year': 1975
    }
]
print(response)

@app.route("/setup")
def setup():
    try:
        # Insert data into the table
        for song in songs_data:
            table.put_item(Item=song)
        print("Data inserted successfully!")

    except NoCredentialsError:
        print("Credentials not available.")
    except PartialCredentialsError:
        print("Incomplete credentials provided.")
    except Exception as e:
        print(f"An error occurred: {e}")


@app.route("/")
def hell():
    return "Hello world, it's great to meet you!"

@app.route("/v1/bestmusic/90s/<string:artist>")
def get_artist(artist):
    #https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client/get_item.html
    resp = client.get_item(
        TableName=dynamodbTableName,
        Key={
            'artist': { 'S': artist }
        }
    )

    item = resp.get('Item')
    if not item:
        return jsonify({'error': 'Artist does not exist'}), 404
    return jsonify({
        'artist': item.get('artist').get('S'),
        'songtitle': item.get('song').get('S'),
        'albumtitle': item.get('album').get('S'),
        'year': item.get('year').get('S')
    })



if __name__ == '__main__':
    app.run(threaded=True,host='0.0.0.0',port=5000)