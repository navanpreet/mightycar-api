from services.api.user import api
from flask import Flask
from flask_pymongo import *
from services.api.config import mongo

app = Flask(__name__)

app.config['MONGO_HOST'] = mongo['MONGO_HOST']
app.config['MONGO_PORT'] = mongo['MONGO_PORT']
app.config['MONGO_DBNAME'] = mongo['MONGO_DBNAME']

db = PyMongo(app, config_prefix="MONGO")

api.init_app(app)
app.run()