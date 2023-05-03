from flask import Flask
from flask import request
from flask import  jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import jsonpickle
import json
from json import JSONEncoder
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.sql.expression import func

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:rodina12345@localhost:5432/bakalarka'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(128))
    username = db.Column(db.String(128))
    surname = db.Column(db.String(128))
    password = db.Column(db.String(128))
    role = db.Column(db.String(128))
    patientsnames = db.Column(db.ARRAY(db.String), nullable=True)
class Statistics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gameName = db.Column(db.String(64))
    nickName = db.Column(db.String(64))
    time = db.Column(db.Integer)
    clicks = db.Column(db.Integer)
    date = db.Column(db.Date)

class CustomEncoder(json.JSONEncoder):
    def default(self, o):
            return o.__dict__
        
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    nickname = data['nickname']
    email = data['email']
    surname = data['surname']
    role = "user"
    patientsnames = []
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    user = User.query.filter_by(nickname=nickname).first()
    if user:
        return jsonify({'message': 'Nickname already registered'}), 409
    else:
        user = User(username=username, password=hashed_password, nickname=nickname, email=email, surname=surname, role = role,patientsnames=patientsnames)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'message': 'Použivateľ zaregistrovaný'})

@app.route('/login', methods=['POST'])
def login():
    print("som tu")
    data = request.get_json()

    
    name = data['nickName']
    password = data['password']

    user = User.query.filter_by(nickname=name).first()

    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        print(access_token)
        
        return jsonify(access_token=access_token, role = user.role)

    else:
        return jsonify({'message': 'Zlé prihlasovačky'}), 401
    
@app.route('/user/addPatient', methods=['POST'])
def addPatient():
    print("som tu")
    data = request.get_json()
    nameDoctor = data['nickNameDoctor']
    namePatient = data['nickNamePatient']
    newName = [namePatient]
    userPatient = User.query.filter_by(nickname=namePatient).first()
    if userPatient :
        
        user = User.query.filter_by(nickname=nameDoctor).first()
        records = User.query.filter(
        User.nickname == nameDoctor,
        func.array_position(User.patientsnames, namePatient).isnot(None)).all()
        if records : 
            print('Pacient už pridany')
            return jsonify({'message': 'Pacient už pridany'}), 403
        else:
            if user.patientsnames is None:
                user.patientsnames = newName
            else:
                print(newName)
                user.patientsnames.extend(newName)
                print(user.patientsnames)
            flag_modified(user, 'patientsnames')
            db.session.commit()
            return jsonify({'message': 'Pacient pridány'}), 200
    else :
        print('Pacient neexistuje')
        return jsonify({'message': 'Pacient neexistuje'}), 403
   
    
@app.route('/statistics', methods=['GET'])
def statistic():
    print("som tu")

    statistic = Statistics.query.all()
    records_list = [{"id": r.id, "gameName": r.gameName, "nickName": r.nickName, "time": r.time, "clicks": r.clicks, "date": r.date} for r in statistic]
    return jsonify(records_list)
    

@app.route('/user', methods=['GET'])
def user():
    print("som tu")
    nickName = request.args.get('nickName')
    print(nickName)
    user = User.query.filter_by(nickname=nickName).first()
    print(user.patientsnames)
    records_list = {"id": user.id, "nickname": user.nickname, "email": user.email, "username": user.username, "surname": user.surname, "password": user.password,"role": user.role,"patientsnames":user.patientsnames}
    return jsonify(records_list)    
    
    
@app.route('/loggame', methods=['POST'])
def logGame():
    print("som tu")
    data = request.get_json()
    print(data)
    nickName = data['user']
    gameName = data['name']
    time = data['time']
    clicks = data['clicks']
    date = data['date']


    gameStatistics = Statistics(nickName=nickName,gameName=gameName, time=time, clicks=clicks,date=date)
    db.session.add(gameStatistics)
    db.session.commit()
    return jsonify({'message': 'Štatistika hry pridaná'})
    

if __name__ == '__main__':
    app.run(debug=True)