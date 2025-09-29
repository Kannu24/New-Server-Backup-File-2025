import os
import sys
from flask import Flask, jsonify, make_response,redirect
from flask_cors import CORS
from flask_swagger_ui import get_swaggerui_blueprint
from test_api_prashant_v6_cs_state_1 import *
import pdb
from test_api_prashant_v6_cs_state_1 import REQUEST_API
import test_api_prashant_v6_cs_state_1
import logging
from werkzeug.middleware.proxy_fix import ProxyFix


app = Flask(__name__)
CORS = CORS(app)


# # Tell Flask to trust one proxy hop (ALB / first reverse proxy)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


#error logs
handler = logging.FileHandler('/home/ubuntu/myproject/flask.log')
handler.setLevel(logging.ERROR)
app.logger.addHandler(handler)



### swagger specific ###
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "ThePriceX | API Document"
    }
)

app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)

### end swagger specific ###



app.register_blueprint(test_api_prashant_v6_cs_state_1.get_blueprint())


@app.errorhandler(400)
def handle_400_error(_error):
    """Return a http 400 error to client"""
    return make_response(jsonify({'error': 'Misunderstood'}), 400)


@app.errorhandler(401)
def handle_401_error(_error):
    """Return a http 401 error to client"""
    return make_response(jsonify({'error': 'Unauthorised'}), 401)


@app.errorhandler(404)
def handle_404_error(_error):
    return make_response(jsonify({'error': 'Not found'}), 404)


@app.errorhandler(500)
def handle_500_error(_error):
    """Return a http 500 error to client"""
    return make_response(jsonify({'error': 'Server error'}), 500)

@app.errorhandler(406)
def handle_406_error(_error):
    """Return a http 500 error to client"""
    return make_response(jsonify({'error': 'Some fields missing'}), 406)



@app.route("/")
def hello():
    return redirect('/swagger')



if __name__ == "__main__":
    app.run(debug=True,host = '0.0.0.0')